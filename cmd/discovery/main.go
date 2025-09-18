package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/jaypipes/ghw/pkg/block"
	"github.com/kairos-io/kairos-challenger/cmd/discovery/client"
	"github.com/kairos-io/kairos-sdk/kcrypt/bus"
	"github.com/kairos-io/kairos-sdk/types"
	"github.com/mudler/go-pluggable"
)

func main() {
	// Check if we're being called as a plugin or CLI mode
	if len(os.Args) > 1 && isEventDefined(os.Args[1]) {
		// Plugin mode - use the go-pluggable interface
		exitCode := RunPluginMode()
		os.Exit(exitCode)
	} else {
		// CLI mode - use flags
		exitCode := RunCLIMode(os.Args[1:])
		os.Exit(exitCode)
	}
}

// RunPluginMode implements the go-pluggable interface
// Returns exit code for testability
func RunPluginMode() int {
	c, err := client.NewClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating client: %v\n", err)
		return 1
	}

	err = c.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error starting plugin: %v\n", err)
		return 1
	}
	return 0
}

// RunCLIMode implements the CLI interface with flags
// Takes args slice and returns exit code for testability
func RunCLIMode(args []string) int {
	// Create a new FlagSet for testability
	fs := flag.NewFlagSet("kcrypt-discovery-challenger", flag.ContinueOnError)

	var (
		partitionName     = fs.String("partition-name", "", "Name of the partition (at least one identifier required)")
		partitionUUID     = fs.String("partition-uuid", "", "UUID of the partition (at least one identifier required)")
		partitionLabel    = fs.String("partition-label", "", "Filesystem label of the partition (at least one identifier required)")
		attempts          = fs.Int("attempts", 30, "Number of attempts to get the passphrase")
		challengerServer  = fs.String("challenger-server", "", "URL of the challenger server (overrides config)")
		enableMDNS        = fs.Bool("mdns", false, "Enable mDNS discovery (overrides config)")
		serverCertificate = fs.String("certificate", "", "Server certificate for verification (overrides config)")
		debug             = fs.Bool("debug", false, "Enable debug logging to show configuration values")
		showHelp          = fs.Bool("help", false, "Show this help message")
		showVersion       = fs.Bool("version", false, "Show version information")
	)

	fs.Usage = func() {
		usageText := fmt.Sprintf(`Usage: kcrypt-discovery-challenger [options]

kcrypt-challenger discovery client - Get decryption passphrases for encrypted partitions

This tool can work in two modes:
  1. Plugin mode: kcrypt-discovery-challenger %s < partition_data.json
  2. CLI mode: kcrypt-discovery-challenger [at least one of --partition-name, --partition-uuid, or --partition-label]

CLI Options:
`, bus.EventDiscoveryPassword)

		fmt.Fprint(os.Stderr, usageText)
		fs.PrintDefaults()

		examplesText := fmt.Sprintf(`
Examples:
  # Get passphrase using partition name only
  kcrypt-discovery-challenger --partition-name=/dev/sda2

  # Get passphrase using UUID only
  kcrypt-discovery-challenger --partition-uuid=12345-abcde

  # Get passphrase using filesystem label only
  kcrypt-discovery-challenger --partition-label=encrypted-data

  # Get passphrase with multiple identifiers (provides more options for matching)
  kcrypt-discovery-challenger --partition-name=/dev/sda2 --partition-uuid=12345-abcde --partition-label=encrypted-data

  # Get passphrase with custom server (override config)
  kcrypt-discovery-challenger --partition-label=encrypted-data --challenger-server=https://my-server.com:8082

  # Plugin mode (for integration with kcrypt)
  echo '{"data": "{\"name\": \"/dev/sda2\", \"uuid\": \"12345-abcde\", \"label\": \"encrypted-data\"}"}' | kcrypt-discovery-challenger %s

Configuration:
  The client reads configuration from Kairos configuration files in /oem, /sysroot/oem, or /tmp/oem
  Key configuration options under kcrypt.challenger:
    - challenger_server: URL of the challenger server
    - mdns: Enable mDNS discovery
    - certificate: Server certificate for verification
`, bus.EventDiscoveryPassword)

		fmt.Fprint(os.Stderr, examplesText)
	}

	err := fs.Parse(args)
	if err != nil {
		return 1
	}

	// Create logger based on debug flag
	var logger types.KairosLogger
	if *debug {
		logger = types.NewKairosLogger("kcrypt-discovery-challenger", "debug", false)
	} else {
		logger = types.NewKairosLogger("kcrypt-discovery-challenger", "error", false)
	}

	if *showHelp {
		fs.Usage()
		return 0
	}

	if *showVersion {
		fmt.Println("kcrypt-challenger discovery client")
		fmt.Println("Part of the Kairos project: https://github.com/kairos-io/kcrypt-challenger")
		return 0
	}

	// Validate required flags - at least one identifier must be provided
	if *partitionName == "" && *partitionUUID == "" && *partitionLabel == "" {
		fmt.Fprintf(os.Stderr, "Error: At least one of partition-name, partition-uuid, or partition-label must be provided\n\n")
		fs.Usage()
		return 1
	}

	// Create client with potential CLI overrides
	c, err := createClientWithOverrides(*challengerServer, *enableMDNS, *serverCertificate, logger, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating client: %v\n", err)
		return 1
	}

	// Create partition object
	partition := &block.Partition{
		Name:            *partitionName,
		UUID:            *partitionUUID,
		FilesystemLabel: *partitionLabel,
	}

	// Log partition information
	logger.Debugf("Partition details:")
	logger.Debugf("  Name: %s", partition.Name)
	logger.Debugf("  UUID: %s", partition.UUID)
	logger.Debugf("  Label: %s", partition.FilesystemLabel)
	logger.Debugf("  Attempts: %d", *attempts)

	// Get the passphrase using the same backend logic as the plugin
	fmt.Fprintf(os.Stderr, "Requesting passphrase for partition %s (UUID: %s, Label: %s)...\n",
		*partitionName, *partitionUUID, *partitionLabel)

	passphrase, err := c.GetPassphrase(partition, *attempts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting passphrase: %v\n", err)

		// Check if log file exists and show relevant information
		if logContent, readErr := os.ReadFile(client.LOGFILE); readErr == nil {
			fmt.Fprintf(os.Stderr, "\nDebug information from %s:\n%s\n", client.LOGFILE, string(logContent))
		}

		return 1
	}

	// Output the passphrase to stdout (this is what tools expect)
	fmt.Print(passphrase)

	fmt.Fprintf(os.Stderr, "\nPassphrase retrieved successfully\n")
	return 0
}

// isEventDefined checks whether an event is defined in the bus.
// It accepts strings or EventType, returns a boolean indicating that
// the event was defined among the events emitted by the bus.
func isEventDefined(i interface{}) bool {
	checkEvent := func(e pluggable.EventType) bool {
		if e == bus.EventDiscoveryPassword {
			return true
		}

		return false
	}

	switch f := i.(type) {
	case string:
		return checkEvent(pluggable.EventType(f))
	case pluggable.EventType:
		return checkEvent(f)
	default:
		return false
	}
}

// createClientWithOverrides creates a client and applies CLI flag overrides to the config
func createClientWithOverrides(serverURL string, enableMDNS bool, certificate string, logger types.KairosLogger, args []string) (*client.Client, error) {
	// Start with the default config from files
	c, err := client.NewClient()
	if err != nil {
		return nil, err
	}

	// Log the original configuration values
	logger.Debugf("Original configuration:")
	logger.Debugf("  Server: %s", c.Config.Kcrypt.Challenger.Server)
	logger.Debugf("  MDNS: %t", c.Config.Kcrypt.Challenger.MDNS)
	logger.Debugf("  Certificate: %s", maskSensitiveString(c.Config.Kcrypt.Challenger.Certificate))

	// Apply CLI overrides if provided
	if serverURL != "" {
		logger.Debugf("Overriding server URL: %s -> %s", c.Config.Kcrypt.Challenger.Server, serverURL)
		c.Config.Kcrypt.Challenger.Server = serverURL
	}

	// For boolean flags, check if the flag was explicitly provided in the args
	mdnsSet := false
	for _, arg := range args {
		if arg == "-mdns" || arg == "--mdns" ||
			strings.HasPrefix(arg, "-mdns=") || strings.HasPrefix(arg, "--mdns=") {
			mdnsSet = true
			break
		}
	}

	if mdnsSet {
		logger.Debugf("Overriding MDNS setting: %t -> %t", c.Config.Kcrypt.Challenger.MDNS, enableMDNS)
		c.Config.Kcrypt.Challenger.MDNS = enableMDNS
	}

	if certificate != "" {
		logger.Debugf("Overriding certificate: %s -> %s",
			maskSensitiveString(c.Config.Kcrypt.Challenger.Certificate),
			maskSensitiveString(certificate))
		c.Config.Kcrypt.Challenger.Certificate = certificate
	}

	// Log the final configuration values
	logger.Debugf("Final configuration:")
	logger.Debugf("  Server: %s", c.Config.Kcrypt.Challenger.Server)
	logger.Debugf("  MDNS: %t", c.Config.Kcrypt.Challenger.MDNS)
	logger.Debugf("  Certificate: %s", maskSensitiveString(c.Config.Kcrypt.Challenger.Certificate))

	return c, nil
}

// maskSensitiveString masks certificate paths/content for logging
func maskSensitiveString(s string) string {
	if s == "" {
		return "<empty>"
	}
	if len(s) <= 10 {
		return strings.Repeat("*", len(s))
	}
	// Show first 3 and last 3 characters with * in between
	return s[:3] + strings.Repeat("*", len(s)-6) + s[len(s)-3:]
}
