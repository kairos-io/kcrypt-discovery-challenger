package client

import (
	"github.com/kairos-io/kairos/pkg/config"
	kconfig "github.com/kairos-io/kcrypt/pkg/config"
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

	c, err := config.Scan(config.Directories(kconfig.ConfigScanDirs...), config.NoLogs)
	if err != nil {
		return result, err
	}

	if err = c.Unmarshal(&result); err != nil {
		return result, err
	}

	return result, nil
}
