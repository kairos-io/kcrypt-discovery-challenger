package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/jaypipes/ghw/pkg/block"
	"github.com/kairos-io/kairos-challenger/cmd/discovery/client"
	"github.com/kairos-io/kairos-challenger/pkg/constants"
	"github.com/kairos-io/kairos-sdk/kcrypt/bus"
	"github.com/kairos-io/kairos-sdk/types"
	"github.com/kairos-io/tpm-helpers"
	"github.com/spf13/cobra"
)

var (
	// Global flags for the get subcommand (passphrase retrieval)
	partitionName     string
	partitionUUID     string
	partitionLabel    string
	attempts          int
	challengerServer  string
	enableMDNS        bool
	serverCertificate string
	debug             bool
)

// rootCmd represents the base command (TPM hash generation)
var rootCmd = &cobra.Command{
	Use:   "kcrypt-discovery-challenger",
	Short: "kcrypt-challenger discovery client",
	Long: `kcrypt-challenger discovery client

This tool provides TPM-based operations for encrypted partition management.
By default, it outputs the TPM hash for this device.

Configuration:
  The client reads configuration from Kairos configuration files in the following directories:
  - /oem (during installation from ISO)
  - /sysroot/oem (on installed systems during initramfs)
  - /tmp/oem (when running in hooks)

  Configuration format (YAML):
    kcrypt:
      challenger:
        challenger_server: "https://my-server.com:8082"  # Server URL
        mdns: true                                       # Enable mDNS discovery
        certificate: "/path/to/server-cert.pem"         # Server certificate
        nv_index: "0x1500000"                           # TPM NV index (offline mode)
        c_index: "0x1500001"                            # TPM certificate index
        tpm_device: "/dev/tpmrm0"                        # TPM device path`,
	Example: `  # Get TPM hash for this device (default)
  kcrypt-discovery-challenger

  # Get passphrase for encrypted partition
  kcrypt-discovery-challenger get --partition-name=/dev/sda2

  # Run plugin event
  kcrypt-discovery-challenger discovery.password`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runTPMHash()
	},
}

// getCmd represents the get command (passphrase retrieval)
var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Get passphrase for encrypted partition",
	Long: `Get passphrase for encrypted partition using TPM attestation.

This command retrieves passphrases for encrypted partitions by communicating
with a challenger server using TPM-based attestation. At least one partition
identifier (name, UUID, or label) must be provided.

The command uses configuration from the root command's config files, but flags
can override specific settings:
  --challenger-server  Override kcrypt.challenger.challenger_server
  --mdns               Override kcrypt.challenger.mdns  
  --certificate        Override kcrypt.challenger.certificate`,
	Example: `  # Get passphrase using partition name
  kcrypt-discovery-challenger get --partition-name=/dev/sda2

  # Get passphrase using UUID  
  kcrypt-discovery-challenger get --partition-uuid=12345-abcde

  # Get passphrase using filesystem label
  kcrypt-discovery-challenger get --partition-label=encrypted-data

  # Get passphrase with multiple identifiers
  kcrypt-discovery-challenger get --partition-name=/dev/sda2 --partition-uuid=12345-abcde --partition-label=encrypted-data

  # Get passphrase with custom server
  kcrypt-discovery-challenger get --partition-label=encrypted-data --challenger-server=https://my-server.com:8082`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		// Validate that at least one partition identifier is provided
		if partitionName == "" && partitionUUID == "" && partitionLabel == "" {
			return fmt.Errorf("at least one of --partition-name, --partition-uuid, or --partition-label must be provided")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGetPassphrase()
	},
}

// pluginCmd represents the plugin event commands
var pluginCmd = &cobra.Command{
	Use:   string(bus.EventDiscoveryPassword),
	Short: fmt.Sprintf("Run %s plugin event", bus.EventDiscoveryPassword),
	Long: fmt.Sprintf(`Run the %s plugin event.

This command runs in plugin mode, reading JSON partition data from stdin
and outputting the passphrase to stdout. This is used for integration 
with kcrypt and other tools.`, bus.EventDiscoveryPassword),
	Example: fmt.Sprintf(`  # Plugin mode (for integration with kcrypt)
  echo '{"data": "{\"name\": \"/dev/sda2\", \"uuid\": \"12345-abcde\", \"label\": \"encrypted-data\"}"}' | kcrypt-discovery-challenger %s`, bus.EventDiscoveryPassword),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runPluginMode()
	},
}

func init() {
	// Global flags (available to all commands)
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug logging")

	// Get command flags (for passphrase retrieval)
	getCmd.Flags().StringVar(&partitionName, "partition-name", "", "Name of the partition (at least one identifier required)")
	getCmd.Flags().StringVar(&partitionUUID, "partition-uuid", "", "UUID of the partition (at least one identifier required)")
	getCmd.Flags().StringVar(&partitionLabel, "partition-label", "", "Filesystem label of the partition (at least one identifier required)")
	getCmd.Flags().IntVar(&attempts, "attempts", 30, "Number of attempts to get the passphrase")
	getCmd.Flags().StringVar(&challengerServer, "challenger-server", "", "URL of the challenger server (overrides config)")
	getCmd.Flags().BoolVar(&enableMDNS, "mdns", false, "Enable mDNS discovery (overrides config)")
	getCmd.Flags().StringVar(&serverCertificate, "certificate", "", "Server certificate for verification (overrides config)")

	// Add subcommands
	rootCmd.AddCommand(getCmd)
	rootCmd.AddCommand(pluginCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// runTPMHash handles the root command - TPM hash generation
func runTPMHash() error {
	// Create logger based on debug flag
	var logger types.KairosLogger
	if debug {
		logger = types.NewKairosLogger("kcrypt-discovery-challenger", "debug", false)
		logger.Debugf("Debug mode enabled for TPM hash generation")
	} else {
		logger = types.NewKairosLogger("kcrypt-discovery-challenger", "error", false)
	}

	// Initialize AK Manager with the standard handle file
	logger.Debugf("Initializing AK Manager with handle file: %s", constants.AKBlobFile)
	akManager, err := tpm.NewAKManager(tpm.WithAKHandleFile(constants.AKBlobFile))
	if err != nil {
		return fmt.Errorf("creating AK manager: %w", err)
	}
	logger.Debugf("AK Manager initialized successfully")

	// Ensure AK exists (create if necessary)
	logger.Debugf("Getting or creating AK")
	_, err = akManager.GetOrCreateAK()
	if err != nil {
		return fmt.Errorf("getting/creating AK: %w", err)
	}
	logger.Debugf("AK obtained/created successfully")

	// Get attestation data (includes EK)
	logger.Debugf("Getting attestation data")
	ek, _, err := akManager.GetAttestationData()
	if err != nil {
		return fmt.Errorf("getting attestation data: %w", err)
	}
	logger.Debugf("Attestation data retrieved successfully")

	// Compute TPM hash from EK
	logger.Debugf("Computing TPM hash from EK")
	tpmHash, err := tpm.DecodePubHash(ek)
	if err != nil {
		return fmt.Errorf("computing TPM hash: %w", err)
	}
	logger.Debugf("TPM hash computed successfully: %s", tpmHash)

	// Output the TPM hash to stdout
	fmt.Print(tpmHash)
	return nil
}

// runGetPassphrase handles the get subcommand - passphrase retrieval
func runGetPassphrase() error {
	// Create logger based on debug flag
	var logger types.KairosLogger
	if debug {
		logger = types.NewKairosLogger("kcrypt-discovery-challenger", "debug", false)
	} else {
		logger = types.NewKairosLogger("kcrypt-discovery-challenger", "error", false)
	}

	// Create client with potential CLI overrides
	c, err := createClientWithOverrides(challengerServer, enableMDNS, serverCertificate, logger)
	if err != nil {
		return fmt.Errorf("creating client: %w", err)
	}

	// Create partition object
	partition := &block.Partition{
		Name:            partitionName,
		UUID:            partitionUUID,
		FilesystemLabel: partitionLabel,
	}

	// Log partition information
	logger.Debugf("Partition details:")
	logger.Debugf("  Name: %s", partition.Name)
	logger.Debugf("  UUID: %s", partition.UUID)
	logger.Debugf("  Label: %s", partition.FilesystemLabel)
	logger.Debugf("  Attempts: %d", attempts)

	// Get the passphrase using the same backend logic as the plugin
	fmt.Fprintf(os.Stderr, "Requesting passphrase for partition %s (UUID: %s, Label: %s)...\n",
		partitionName, partitionUUID, partitionLabel)

	passphrase, err := c.GetPassphrase(partition, attempts)
	if err != nil {
		return fmt.Errorf("getting passphrase: %w", err)
	}

	// Output the passphrase to stdout (this is what tools expect)
	fmt.Print(passphrase)
	fmt.Fprintf(os.Stderr, "\nPassphrase retrieved successfully\n")
	return nil
}

// runPluginMode handles plugin event commands
func runPluginMode() error {
	// In plugin mode, use quiet=true to log to file instead of console
	// Log level depends on debug flag, write logs to /var/log/kairos/kcrypt-discovery-challenger.log
	var logLevel string
	if debug {
		logLevel = "debug"
	} else {
		logLevel = "error"
	}

	logger := types.NewKairosLogger("kcrypt-discovery-challenger", logLevel, true)
	c, err := client.NewClientWithLogger(logger)
	if err != nil {
		return fmt.Errorf("creating client: %w", err)
	}

	err = c.Start()
	if err != nil {
		return fmt.Errorf("starting plugin: %w", err)
	}
	return nil
}

// createClientWithOverrides creates a client and applies CLI flag overrides to the config
func createClientWithOverrides(serverURL string, enableMDNS bool, certificate string, logger types.KairosLogger) (*client.Client, error) {
	// Start with the default config from files and pass the logger
	c, err := client.NewClientWithLogger(logger)
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

	// For boolean flags, we can directly use the value since Cobra handles it properly
	if enableMDNS {
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
