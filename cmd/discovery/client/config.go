package client

import (
	"github.com/kairos-io/kairos-sdk/collector"
	kconfig "github.com/kairos-io/kcrypt/pkg/config"
	"gopkg.in/yaml.v3"
)

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
	if err := o.Apply(collector.Directories(append(kconfig.ConfigScanDirs, "/tmp/oem")...)); err != nil {
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
