package client

import (
	"github.com/kairos-io/kairos-sdk/types"
)

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

// newEmptyConfig returns an empty config
// The actual config is now passed via the DiscoveryPasswordPayload JSON from the caller
func newEmptyConfig() Config {
	return Config{}
}
