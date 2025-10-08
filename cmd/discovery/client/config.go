package client

import (
	"github.com/kairos-io/kairos-sdk/collector"
	"github.com/kairos-io/kairos-sdk/types"
	"gopkg.in/yaml.v3"
)

// There are the directories under which we expect to find kairos configuration.
// When we are booted from an iso (during installation), configuration is expected
// under `/oem`. When we are booting an installed system (in initramfs phase),
// the path is `/sysroot/oem`.
// When we run the challenger in hooks, we may have the config under /tmp/oem
// During manual install (kairos-agent manual-install), kairos-agent stores config in /run/cos/oem
var confScanDirs = []string{"/oem", "/sysroot/oem", "/tmp/oem", "/run/cos/oem"}

type Client struct {
	Config Config
	Logger types.KairosLogger
}

type Config struct {
	Kcrypt struct {
		Challenger struct {
			MDNS        bool   `yaml:"mdns,omitempty"`
			Server      string `yaml:"challenger_server,omitempty"`
			NVIndex     string `yaml:"nv_index,omitempty"` // Non-volatile index memory: where we store the encrypted passphrase (offline mode)
			CIndex      string `yaml:"c_index,omitempty"`  // Certificate index: this is where the rsa pair that decrypts the passphrase lives
			TPMDevice   string `yaml:"tpm_device,omitempty"`
			Certificate string `yaml:"certificate,omitempty"`
		}
	}
}

func unmarshalConfig(logger types.KairosLogger) (Config, error) {
	var result Config

	logger.Debugf("Starting config unmarshal from directories: %v", confScanDirs)

	// First scan config files from standard directories
	o := &collector.Options{NoLogs: true, MergeBootCMDLine: false}
	if err := o.Apply(collector.Directories(confScanDirs...)); err != nil {
		logger.Debugf("Error applying collector options: %v", err)
		return result, err
	}

	c, err := collector.Scan(o, func(d []byte) ([]byte, error) {
		return d, nil
	})
	if err != nil {
		logger.Debugf("Error scanning config directories: %v", err)
		return result, err
	}

	a, _ := c.String()
	logger.Debugf("Config from files (before cmdline merge): %s", a)

	err = yaml.Unmarshal([]byte(a), &result)
	if err != nil {
		logger.Debugf("Error unmarshaling file config: %v", err)
		return result, err
	}

	logger.Debugf("File-based config parsed - Server: %s, MDNS: %t, Certificate: %s",
		result.Kcrypt.Challenger.Server,
		result.Kcrypt.Challenger.MDNS,
		maskSensitive(result.Kcrypt.Challenger.Certificate))

	// Parse cmdline and merge with file-based config
	// This is crucial for the encrypted OEM partition scenario where the config
	// is on the encrypted partition but we need it to decrypt that partition.
	// The cmdline parameters (e.g., kairos.kcrypt.challenger_server=...) take precedence.
	logger.Debugf("Attempting to parse cmdline from /proc/cmdline")
	cmdlineConfig, err := collector.ParseCmdLine("", func(d []byte) ([]byte, error) {
		// No filtering needed - we want all cmdline params
		return d, nil
	})
	if err != nil {
		// Cmdline parsing is optional - may not be available in all environments
		logger.Debugf("Could not parse cmdline (this is OK in some environments): %v", err)
		return result, nil
	}

	// Merge cmdline config into result - this will override file-based values
	cmdlineStr, _ := cmdlineConfig.String()
	logger.Debugf("Cmdline config parsed: %s", cmdlineStr)

	// The cmdline parameters are written as "kairos.kcrypt.challenger_server=value" which ParseCmdLine converts to:
	// kairos:
	//   kcrypt:
	//     challenger_server: value   # NO "challenger" level!
	//     mdns: true
	// We need to extract the values from under kairos.kcrypt and map them to our Config.Kcrypt.Challenger struct
	var cmdlineWrapper struct {
		Kairos struct {
			Kcrypt struct {
				MDNS        bool   `yaml:"mdns,omitempty"`
				Server      string `yaml:"challenger_server,omitempty"`
				NVIndex     string `yaml:"nv_index,omitempty"`
				CIndex      string `yaml:"c_index,omitempty"`
				TPMDevice   string `yaml:"tpm_device,omitempty"`
				Certificate string `yaml:"certificate,omitempty"`
			} `yaml:"kcrypt"`
		} `yaml:"kairos"`
	}

	err = yaml.Unmarshal([]byte(cmdlineStr), &cmdlineWrapper)
	if err != nil {
		// If we can't parse cmdline config, just continue with file-based config
		logger.Debugf("Could not unmarshal cmdline config: %v", err)
		return result, nil
	}

	// Extract the kcrypt config from under the "kairos" wrapper
	cmdlineKcrypt := cmdlineWrapper.Kairos.Kcrypt

	logger.Debugf("Cmdline kcrypt values - Server: %s, MDNS: %t, Certificate: %s, NVIndex: %s, CIndex: %s, TPMDevice: %s",
		cmdlineKcrypt.Server,
		cmdlineKcrypt.MDNS,
		maskSensitive(cmdlineKcrypt.Certificate),
		cmdlineKcrypt.NVIndex,
		cmdlineKcrypt.CIndex,
		cmdlineKcrypt.TPMDevice)

	// Override file-based config with cmdline values if they exist
	// Map from kairos.kcrypt.* (flat) to our Config.Kcrypt.Challenger.* (nested) structure
	overrideCount := 0
	if cmdlineKcrypt.Server != "" {
		logger.Debugf("Overriding Server from cmdline: %s -> %s", result.Kcrypt.Challenger.Server, cmdlineKcrypt.Server)
		result.Kcrypt.Challenger.Server = cmdlineKcrypt.Server
		overrideCount++
	}
	if cmdlineKcrypt.MDNS {
		logger.Debugf("Overriding MDNS from cmdline: %t -> %t", result.Kcrypt.Challenger.MDNS, cmdlineKcrypt.MDNS)
		result.Kcrypt.Challenger.MDNS = cmdlineKcrypt.MDNS
		overrideCount++
	}
	if cmdlineKcrypt.Certificate != "" {
		logger.Debugf("Overriding Certificate from cmdline")
		result.Kcrypt.Challenger.Certificate = cmdlineKcrypt.Certificate
		overrideCount++
	}
	if cmdlineKcrypt.NVIndex != "" {
		logger.Debugf("Overriding NVIndex from cmdline: %s -> %s", result.Kcrypt.Challenger.NVIndex, cmdlineKcrypt.NVIndex)
		result.Kcrypt.Challenger.NVIndex = cmdlineKcrypt.NVIndex
		overrideCount++
	}
	if cmdlineKcrypt.CIndex != "" {
		logger.Debugf("Overriding CIndex from cmdline: %s -> %s", result.Kcrypt.Challenger.CIndex, cmdlineKcrypt.CIndex)
		result.Kcrypt.Challenger.CIndex = cmdlineKcrypt.CIndex
		overrideCount++
	}
	if cmdlineKcrypt.TPMDevice != "" {
		logger.Debugf("Overriding TPMDevice from cmdline: %s -> %s", result.Kcrypt.Challenger.TPMDevice, cmdlineKcrypt.TPMDevice)
		result.Kcrypt.Challenger.TPMDevice = cmdlineKcrypt.TPMDevice
		overrideCount++
	}

	logger.Infof("Config merge complete - %d values overridden from cmdline", overrideCount)
	logger.Infof("Final config - Server: %s, MDNS: %t, Certificate: %s, NVIndex: %s, CIndex: %s, TPMDevice: %s",
		result.Kcrypt.Challenger.Server,
		result.Kcrypt.Challenger.MDNS,
		maskSensitive(result.Kcrypt.Challenger.Certificate),
		result.Kcrypt.Challenger.NVIndex,
		result.Kcrypt.Challenger.CIndex,
		result.Kcrypt.Challenger.TPMDevice)

	return result, nil
}

// maskSensitive masks sensitive strings for logging (shows first 10 and last 10 chars)
func maskSensitive(s string) string {
	if s == "" {
		return "<empty>"
	}
	if len(s) <= 20 {
		return "***"
	}
	return s[:10] + "..." + s[len(s)-10:]
}
