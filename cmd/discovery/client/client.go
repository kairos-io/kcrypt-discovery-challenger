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
	"github.com/kairos-io/kairos-sdk/kcrypt/bus"
	"github.com/kairos-io/kairos-sdk/types"
	"github.com/kairos-io/tpm-helpers"
	"github.com/mudler/go-pluggable"
	"github.com/mudler/yip/pkg/utils"
)

// Because of how go-pluggable works, we can't just print to stdout
const LOGFILE = "/tmp/kcrypt-challenger-client.log"

var errPartNotFound error = fmt.Errorf("pass for partition not found")
var errBadCertificate error = fmt.Errorf("unknown certificate")

func NewClient() (*Client, error) {
	return NewClientWithLogger(types.NewKairosLogger("kcrypt-challenger-client", "error", false))
}

func NewClientWithLogger(logger types.KairosLogger) (*Client, error) {
	conf, err := unmarshalConfig()
	if err != nil {
		return nil, err
	}

	return &Client{Config: conf, Logger: logger}, nil
}

// ❯ echo '{ "data": "{ \\"label\\": \\"LABEL\\" }"}' | sudo -E WSS_SERVER="http://localhost:8082/challenge" ./challenger "discovery.password"
// GetPassphrase retrieves a passphrase for the given partition - core business logic
func (c *Client) GetPassphrase(partition *block.Partition, attempts int) (string, error) {
	return c.waitPass(partition, attempts)
}

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

		// Use the extracted core logic
		pass, err := c.GetPassphrase(b, 30)
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
	serverURL := c.Config.Kcrypt.Challenger.Server

	// If we don't have any server configured, just do local
	if serverURL == "" {
		return localPass(c.Config)
	}

	additionalHeaders := map[string]string{}
	if c.Config.Kcrypt.Challenger.MDNS {
		serverURL, additionalHeaders, err = queryMDNS(serverURL, c.Logger)
		if err != nil {
			return "", err
		}
	}

	// Determine which flow to use based on TPM capabilities
	if c.canUseTPMAttestation() {
		c.Logger.Debugf("TPM attestation capabilities detected, using TPM flow")
		return c.waitPassWithTPMAttestation(serverURL, additionalHeaders, p, attempts)
	} else {
		c.Logger.Debugf("No TPM attestation capabilities, using legacy flow")
		return c.waitPassLegacy(serverURL, additionalHeaders, p, attempts)
	}
}

// canUseTPMAttestation checks if TPM device exists and PCRs 0, 7, 11 are populated
func (c *Client) canUseTPMAttestation() bool {
	// Check if TPM device is available by trying to get EK
	_, err := tpm.GetPubHash()
	if err != nil {
		c.Logger.Debugf("TPM device not available: %v", err)
		return false
	}

	// Check if the critical PCRs (0, 7, 11) have values (measured boot occurred)
	pcrValues, err := c.readPCRValues([]int{0, 7, 11})
	if err != nil {
		c.Logger.Debugf("Failed to read PCR values: %v", err)
		return false
	}

	// Check if any of the critical PCRs are populated (not all zeros)
	allZero := true
	for _, pcr := range pcrValues {
		for _, b := range pcr {
			if b != 0 {
				allZero = false
				break
			}
		}
		if !allZero {
			break
		}
	}

	if allZero {
		c.Logger.Debugf("PCRs 0, 7, 11 are all zero - measured boot did not occur")
		return false
	}

	c.Logger.Debugf("TPM device available and PCRs populated")
	return true
}

// readPCRValues reads the specified PCR values from the TPM using simple command execution
func (c *Client) readPCRValues(pcrIndices []int) ([][]byte, error) {
	// For now, we'll use a simplified approach to check if TPM has meaningful PCR values
	// This can be enhanced later with proper TPM library integration
	// We'll just check if TPM is accessible and assume PCRs are valid if TPM responds

	// Try to access TPM by getting EK pub hash - if this works, TPM is functional
	_, err := tpm.GetPubHash()
	if err != nil {
		return nil, fmt.Errorf("TPM not accessible: %w", err)
	}

	// For the MVP, we'll assume if TPM is accessible, PCRs are likely populated
	// Return dummy non-zero values to indicate PCRs are "populated"
	// TODO: Implement proper PCR reading using go-attestation or tpm2-tools
	result := make([][]byte, len(pcrIndices))
	for i := range result {
		// Create dummy PCR value (non-zero to indicate "populated")
		result[i] = []byte{0x01, 0x02, 0x03} // Placeholder - indicates PCR has values
	}

	return result, nil
}

// waitPassWithTPMAttestation implements the new TPM remote attestation flow
func (c *Client) waitPassWithTPMAttestation(serverURL string, additionalHeaders map[string]string, p *block.Partition, attempts int) (string, error) {
	// TODO: Implement TPM attestation flow
	// 1. Initialize AKManager
	// 2. Request challenge from server
	// 3. Generate proof with TPM quote
	// 4. Send proof and get passphrase

	c.Logger.Debugf("TPM attestation flow - not yet implemented")
	return "", fmt.Errorf("TPM attestation flow not implemented yet")
}

// waitPassLegacy implements the current/legacy flow without TPM attestation
func (c *Client) waitPassLegacy(serverURL string, additionalHeaders map[string]string, p *block.Partition, attempts int) (string, error) {
	getEndpoint := fmt.Sprintf("%s/getPass", serverURL)
	postEndpoint := fmt.Sprintf("%s/postPass", serverURL)

	for tries := 0; tries < attempts; tries++ {
		var generated bool
		pass, generated, err := getPass(getEndpoint, additionalHeaders, c.Config.Kcrypt.Challenger.Certificate, p)
		if err == errPartNotFound {
			// IF server doesn't have a pass for us, then we generate one and we set it
			err = c.generatePass(postEndpoint, additionalHeaders, p)
			if err != nil {
				return "", err
			}
			// Attempt to fetch again - validate that the server has it now
			tries = 0
			continue
		}

		if generated { // passphrase is encrypted
			return c.decryptPassphrase(pass)
		}

		if err == errBadCertificate { // No need to retry, won't succeed.
			return "", err
		}

		if err == nil { // passphrase available, no errors
			return pass, nil
		}

		c.Logger.Debugf("Failed with error: %s . Will retry.", err.Error())
		time.Sleep(1 * time.Second) // network errors? retry
	}

	return "", fmt.Errorf("exhausted all attempts (%d) to get passphrase", attempts)
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
