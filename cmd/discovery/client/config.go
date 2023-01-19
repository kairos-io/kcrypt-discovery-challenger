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
			Server    string `yaml:"challenger_server,omitempty"`
			NVIndex   string `yaml:"nv_index,omitempty"`
			CIndex    string `yaml:"c_index,omitempty"`
			TPMDevice string `yaml:"tpm_device,omitempty"`
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
