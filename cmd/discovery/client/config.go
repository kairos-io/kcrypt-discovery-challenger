package client

import (
	"github.com/kairos-io/kairos-sdk/collector"
	"gopkg.in/yaml.v3"
)

// There are the directories under which we expect to find kairos configuration.
// When we are booted from an iso (during installation), configuration is expected
// under `/oem`. When we are booting an installed system (in initramfs phase),
// the path is `/sysroot/oem`.
// When we run the challenger in hooks, we may have the config under /tmp/oem
var confScanDirs = []string{"/oem", "/sysroot/oem", "/tmp/oem"}

type Client struct {
	Config Config
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

func unmarshalConfig() (Config, error) {
	var result Config

	o := &collector.Options{NoLogs: true, MergeBootCMDLine: false}
	if err := o.Apply(collector.Directories(confScanDirs...)); err != nil {
		return result, err
	}

	c, err := collector.Scan(o, func(d []byte) ([]byte, error) {
		return d, nil
	})
	if err != nil {
		return result, err
	}

	a, _ := c.String()
	err = yaml.Unmarshal([]byte(a), &result)
	if err != nil {
		return result, err
	}

	return result, nil
}
