package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/jaypipes/ghw/pkg/block"
	"github.com/kairos-io/kairos-challenger/pkg/constants"
	"github.com/kairos-io/kcrypt/pkg/bus"
	"github.com/kairos-io/tpm-helpers"
	"github.com/mudler/go-pluggable"
	"github.com/mudler/yip/pkg/utils"
)

var errPartNotFound error = fmt.Errorf("pass for partition not found")

func NewClient() (*Client, error) {
	conf, err := unmarshalConfig()
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
	// IF we don't have any server configured, just do local
	if c.Config.Kcrypt.Challenger.Server == "" {
		return localPass(c.Config)
	}

	challengeEndpoint := fmt.Sprintf("%s/getPass", c.Config.Kcrypt.Challenger.Server)
	postEndpoint := fmt.Sprintf("%s/postPass", c.Config.Kcrypt.Challenger.Server)

	// IF server doesn't have a pass for us, then we generate one and we set it
	if _, _, err := getPass(challengeEndpoint, p); err == errPartNotFound {
		rand := utils.RandomString(32)
		pass, err := tpm.EncodeBlob([]byte(rand))
		if err != nil {
			return "", err
		}
		bpass := base64.RawURLEncoding.EncodeToString(pass)

		opts := []tpm.Option{
			tpm.WithAdditionalHeader("label", p.Label),
			tpm.WithAdditionalHeader("name", p.Name),
			tpm.WithAdditionalHeader("uuid", p.UUID),
		}
		conn, err := tpm.Connection(postEndpoint, opts...)
		if err != nil {
			return "", err
		}
		err = conn.WriteJSON(map[string]string{"passphrase": bpass, constants.GeneratedByKey: constants.TPMSecret})
		if err != nil {
			return rand, err
		}
	}

	for tries := 0; tries < attempts; tries++ {
		var generated bool
		pass, generated, err = getPass(challengeEndpoint, p)
		if generated { // passphrase is encrypted
			return c.decryptPassphrase(pass)
		}

		if err == nil || err == errPartNotFound { // passphrase not encrypted or not available
			return
		}

		time.Sleep(1 * time.Second) // network errors? retry
	}

	return
}

// decryptPassphrase decodes (base64) and decrypts the passphrase returned
// by the challenger server.
func (c *Client) decryptPassphrase(pass string) (string, error) {
	blob, err := base64.RawURLEncoding.DecodeString(pass)
	if err != nil {
		return "", err
	}

	// Decrypt and return it to unseal the LUKS volume
	opts := []tpm.TPMOption{}
	if c.Config.Kcrypt.Challenger.CIndex != "" {
		opts = append(opts, tpm.WithIndex(c.Config.Kcrypt.Challenger.CIndex))
	}
	if c.Config.Kcrypt.Challenger.TPMDevice != "" {
		opts = append(opts, tpm.WithDevice(c.Config.Kcrypt.Challenger.TPMDevice))
	}
	passBytes, err := tpm.DecodeBlob(blob, opts...)

	return string(passBytes), err
}
