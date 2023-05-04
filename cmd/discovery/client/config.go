package client

import (
	"github.com/kairos-io/kairos/v2/pkg/config"
	"github.com/kairos-io/kairos/v2/pkg/config/collector"
	kconfig "github.com/kairos-io/kcrypt/pkg/config"
	"gopkg.in/yaml.v3"
)

type Client struct {
	Config Config
}

type Config struct {
	Kcrypt struct {
		Challenger struct {
			Server string `yaml:"challenger_server,omitempty"`
			// Non-volatile index memory: where we store the encrypted passphrase (offline mode)
			NVIndex string `yaml:"nv_index,omitempty"`
			// Certificate index: this is where the rsa pair that decrypts the passphrase lives
			CIndex      string `yaml:"c_index,omitempty"`
			TPMDevice   string `yaml:"tpm_device,omitempty"`
			Certificate string `yaml:"certificate,omitempty"`
		}
	}
}

func unmarshalConfig() (Config, error) {
	var result Config

	o := &collector.Options{NoLogs: true}
	if err := o.Apply(collector.Directories(kconfig.ConfigScanDirs...)); err != nil {
		return result, err
	}

	c, err := collector.Scan(o, config.FilterKeys)
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
