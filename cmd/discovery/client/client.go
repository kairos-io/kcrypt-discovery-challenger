package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/jaypipes/ghw/pkg/block"
	"github.com/kairos-io/kairos-challenger/pkg/constants"
	"github.com/kairos-io/kairos-challenger/pkg/payload"
	"github.com/kairos-io/kcrypt/pkg/bus"
	"github.com/kairos-io/tpm-helpers"
	"github.com/mudler/go-pluggable"
	"github.com/mudler/yip/pkg/utils"
)

// Because of how go-pluggable works, we can't just print to stdout
const LOGFILE = "/tmp/kcrypt-challenger-client.log"

var errPartNotFound error = fmt.Errorf("pass for partition not found")
var errBadCertificate error = fmt.Errorf("unknown certificate")

func NewClient() (*Client, error) {
	conf, err := unmarshalConfig()
	if err != nil {
		return nil, err
	}

	return &Client{Config: conf}, nil
}

// ❯ echo '{ "data": "{ \\"label\\": \\"LABEL\\" }"}' | sudo -E WSS_SERVER="http://localhost:8082/challenge" ./challenger "discovery.password"
func (c *Client) Start() error {
	if err := os.RemoveAll(LOGFILE); err != nil { // Start fresh
		return fmt.Errorf("removing the logfile: %w", err)
	}

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

func (c *Client) generatePass(postEndpoint string, headers map[string]string, p *block.Partition) error {

	rand := utils.RandomString(32)
	pass, err := tpm.EncryptBlob([]byte(rand))
	if err != nil {
		return err
	}
	bpass := base64.RawURLEncoding.EncodeToString(pass)

	opts := []tpm.Option{
		tpm.WithCAs([]byte(c.Config.Kcrypt.Challenger.Certificate)),
		tpm.AppendCustomCAToSystemCA,
		tpm.WithAdditionalHeader("label", p.FilesystemLabel),
		tpm.WithAdditionalHeader("name", p.Name),
		tpm.WithAdditionalHeader("uuid", p.UUID),
	}
	for k, v := range headers {
		opts = append(opts, tpm.WithAdditionalHeader(k, v))
	}

	conn, err := tpm.Connection(postEndpoint, opts...)
	if err != nil {
		return err
	}

	return conn.WriteJSON(payload.Data{Passphrase: bpass, GeneratedBy: constants.TPMSecret})
}

func (c *Client) waitPass(p *block.Partition, attempts int) (pass string, err error) {
	additionalHeaders := map[string]string{}
	serverURL := c.Config.Kcrypt.Challenger.Server

	// If we don't have any server configured, just do local
	if serverURL == "" {
		return localPass(c.Config)
	}

	if c.Config.Kcrypt.Challenger.MDNS {
		serverURL, additionalHeaders, err = queryMDNS(serverURL)
	}

	getEndpoint := fmt.Sprintf("%s/getPass", serverURL)
	postEndpoint := fmt.Sprintf("%s/postPass", serverURL)

	for tries := 0; tries < attempts; tries++ {
		var generated bool
		pass, generated, err = getPass(getEndpoint, additionalHeaders, c.Config.Kcrypt.Challenger.Certificate, p)
		if err == errPartNotFound {
			// IF server doesn't have a pass for us, then we generate one and we set it
			err = c.generatePass(postEndpoint, additionalHeaders, p)
			if err != nil {
				return
			}
			// Attempt to fetch again - validate that the server has it now
			tries = 0
			continue
		}

		if generated { // passphrase is encrypted
			return c.decryptPassphrase(pass)
		}

		if err == errBadCertificate { // No need to retry, won't succeed.
			return
		}

		if err == nil { // passphrase available, no errors
			return
		}

		logToFile("Failed with error: %s . Will retry.\n", err.Error())
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
	passBytes, err := tpm.DecryptBlob(blob, opts...)

	return string(passBytes), err
}

func logToFile(format string, a ...any) {
	s := fmt.Sprintf(format, a...)
	file, err := os.OpenFile(LOGFILE, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	file.WriteString(s)
}
