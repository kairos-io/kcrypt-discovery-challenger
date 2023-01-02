package client

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/jaypipes/ghw/pkg/block"
	"github.com/kairos-io/go-tpm"
	"github.com/kairos-io/kcrypt/pkg/bus"
	kconfig "github.com/kairos-io/kcrypt/pkg/config"
	"github.com/mudler/go-pluggable"
	"github.com/pkg/errors"
)

type Client struct {
	Config kconfig.Config
}

func NewClient() (*Client, error) {
	conf, err := kconfig.GetConfiguration(kconfig.ConfigScanDirs)
	if err != nil {
		return nil, err
	}

	return &Client{Config: conf}, nil
}

// ❯ echo '{ "data": "{ \\"label\\": \\"LABEL\\" }"}' | sudo -E WSS_SERVER="http://localhost:8082/challenge" ./challenger "discovery.password"
func (c *Client) Start() error {
	factory := pluggable.NewPluginFactory()

	// Input: bus.EventInstallPayload
	// Expected output: map[string]string{}
	factory.Add(bus.EventDiscoveryPassword, func(e *pluggable.Event) pluggable.EventResponse {

		b := &block.Partition{}
		err := json.Unmarshal([]byte(e.Data), b)
		if err != nil {
			return pluggable.EventResponse{
				Error: fmt.Sprintf("failed reading partitions: %s", err.Error()),
			}
		}

		pass, err := c.waitPass(b, 30)
		if err != nil {
			return pluggable.EventResponse{
				Error: fmt.Sprintf("failed getting pass: %s", err.Error()),
			}
		}

		return pluggable.EventResponse{
			Data: pass,
		}
	})

	return factory.Run(pluggable.EventType(os.Args[1]), os.Stdin, os.Stdout)
}

func (c *Client) waitPass(p *block.Partition, attempts int) (pass string, err error) {
	// TODO: Why are we retrying?
	// We don't need to retry if there is no matching secret.
	// TODO: Check if the request was successful and if the error was about
	// non-matching sealed volume, let's not retry.
	for tries := 0; tries < attempts; tries++ {
		if c.Config.Kcrypt.Server == "" {
			err = fmt.Errorf("no server configured")
			continue
		}

		pass, err = c.getPass(c.Config.Kcrypt.Server, p)
		if pass != "" || err == nil {
			return
		}
		if err != nil {
			return
		}
		time.Sleep(1 * time.Second)
	}
	return
}

func (c *Client) getPass(server string, partition *block.Partition) (string, error) {
	// TODO: This results in unexpected end of file when the other side closes the connection
	// even when the passphrase is found. This shouldn't happen.
	msg, err := tpm.Get(server,
		tpm.WithAdditionalHeader("label", partition.Label),
		tpm.WithAdditionalHeader("name", partition.Name),
		tpm.WithAdditionalHeader("uuid", partition.UUID))
	if err != nil {
		return "", err
	}
	result := map[string]interface{}{}
	err = json.Unmarshal(msg, &result)
	if err != nil {
		return "", errors.Wrap(err, string(msg))
	}
	p, ok := result["passphrase"]
	if ok {
		return fmt.Sprint(p), nil
	}
	return "", fmt.Errorf("pass for partition not found")
}
