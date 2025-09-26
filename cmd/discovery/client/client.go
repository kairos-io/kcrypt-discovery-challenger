package client

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/google/go-attestation/attest"
	"github.com/gorilla/websocket"
	"github.com/jaypipes/ghw/pkg/block"
	"github.com/kairos-io/kairos-sdk/kcrypt/bus"
	"github.com/kairos-io/kairos-sdk/types"
	"github.com/kairos-io/tpm-helpers"
	"github.com/mudler/go-pluggable"

	"github.com/kairos-io/kairos-challenger/pkg/constants"
)

// Retry delays for different failure types
const (
	TPMRetryDelay     = 100 * time.Millisecond // Brief delay for TPM hardware busy/unavailable
	NetworkRetryDelay = 1 * time.Second        // Longer delay for network/server issues
)

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

func (c *Client) Start(eventType pluggable.EventType) error {
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

	return factory.Run(eventType, os.Stdin, c.Logger)
}

// ❯ echo '{ "data": "{ \\"label\\": \\"LABEL\\" }"}' | sudo -E WSS_SERVER="http://localhost:8082/challenge" ./challenger "discovery.password"
// GetPassphrase retrieves a passphrase for the given partition - core business logic
func (c *Client) GetPassphrase(partition *block.Partition, attempts int) (string, error) {
	serverURL := c.Config.Kcrypt.Challenger.Server

	// If we don't have any server configured, just do local
	if serverURL == "" {
		return localPass(c.Config)
	}

	additionalHeaders := map[string]string{}
	var err error
	if c.Config.Kcrypt.Challenger.MDNS {
		serverURL, additionalHeaders, err = queryMDNS(serverURL, c.Logger)
		if err != nil {
			return "", err
		}
	}

	c.Logger.Debugf("Starting TPM attestation flow with server: %s", serverURL)
	return c.waitPassWithTPMAttestation(serverURL, additionalHeaders, partition, attempts)
}

// waitPassWithTPMAttestation implements the new TPM remote attestation flow over WebSocket
func (c *Client) waitPassWithTPMAttestation(serverURL string, additionalHeaders map[string]string, p *block.Partition, attempts int) (string, error) {
	attestationEndpoint := fmt.Sprintf("%s/tpm-attestation", serverURL)
	c.Logger.Debugf("Debug: TPM attestation endpoint: %s", attestationEndpoint)

	for tries := 0; tries < attempts; tries++ {
		c.Logger.Debugf("Debug: TPM attestation attempt %d/%d", tries+1, attempts)

		// Step 1: Initialize AK Manager
		c.Logger.Debugf("Debug: Initializing AK Manager with handle file: %s", constants.AKBlobFile)
		akManager, err := tpm.NewAKManager(tpm.WithAKHandleFile(constants.AKBlobFile))
		if err != nil {
			c.Logger.Debugf("Failed to create AK manager: %v", err)
			time.Sleep(TPMRetryDelay)
			continue
		}
		c.Logger.Debugf("Debug: AK Manager initialized successfully")

		// Step 2: Ensure AK exists
		c.Logger.Debugf("Debug: Getting or creating AK")
		_, err = akManager.GetOrCreateAK()
		if err != nil {
			c.Logger.Debugf("Failed to get/create AK: %v", err)
			time.Sleep(TPMRetryDelay)
			continue
		}
		c.Logger.Debugf("Debug: AK obtained/created successfully")

		// Step 3: Start WebSocket-based attestation flow
		c.Logger.Debugf("Debug: Starting WebSocket-based attestation flow")
		passphrase, err := c.performTPMAttestation(attestationEndpoint, additionalHeaders, akManager, p)
		if err != nil {
			c.Logger.Debugf("Failed TPM attestation: %v", err)
			time.Sleep(NetworkRetryDelay)
			continue
		}

		return passphrase, nil
	}

	return "", fmt.Errorf("exhausted all attempts (%d) for TPM attestation", attempts)
}

// performTPMAttestation handles the complete attestation flow over a single WebSocket connection
func (c *Client) performTPMAttestation(endpoint string, additionalHeaders map[string]string, akManager *tpm.AKManager, p *block.Partition) (string, error) {
	c.Logger.Debugf("Debug: Creating WebSocket connection to endpoint: %s", endpoint)
	c.Logger.Debugf("Debug: Partition details - Label: %s, Name: %s, UUID: %s", p.FilesystemLabel, p.Name, p.UUID)
	c.Logger.Debugf("Debug: Certificate length: %d", len(c.Config.Kcrypt.Challenger.Certificate))

	// Create WebSocket connection
	opts := []tpm.Option{
		tpm.WithAdditionalHeader("label", p.FilesystemLabel),
		tpm.WithAdditionalHeader("name", p.Name),
		tpm.WithAdditionalHeader("uuid", p.UUID),
	}

	// Only add certificate options if a certificate is provided
	if len(c.Config.Kcrypt.Challenger.Certificate) > 0 {
		c.Logger.Debugf("Debug: Adding certificate validation options")
		opts = append(opts,
			tpm.WithCAs([]byte(c.Config.Kcrypt.Challenger.Certificate)),
			tpm.AppendCustomCAToSystemCA,
		)
	} else {
		c.Logger.Debugf("Debug: No certificate provided, using insecure connection")
	}
	for k, v := range additionalHeaders {
		opts = append(opts, tpm.WithAdditionalHeader(k, v))
	}
	c.Logger.Debugf("Debug: WebSocket options configured, attempting connection...")

	// Add connection timeout to prevent hanging indefinitely
	type connectionResult struct {
		conn interface{}
		err  error
	}

	done := make(chan connectionResult, 1)

	go func() {
		c.Logger.Debugf("Debug: Using tpm.AttestationConnection for new TPM flow")
		conn, err := tpm.AttestationConnection(endpoint, opts...)
		c.Logger.Debugf("Debug: tpm.AttestationConnection returned with err: %v", err)
		done <- connectionResult{conn: conn, err: err}
	}()

	var conn *websocket.Conn
	select {
	case result := <-done:
		if result.err != nil {
			c.Logger.Debugf("Debug: WebSocket connection failed: %v", result.err)
			return "", fmt.Errorf("creating WebSocket connection: %w", result.err)
		}
		var ok bool
		conn, ok = result.conn.(*websocket.Conn)
		if !ok {
			return "", fmt.Errorf("unexpected connection type")
		}
		c.Logger.Debugf("Debug: WebSocket connection established successfully")
	case <-time.After(10 * time.Second):
		c.Logger.Debugf("Debug: WebSocket connection timed out after 10 seconds")
		return "", fmt.Errorf("WebSocket connection timed out")
	}

	defer conn.Close() //nolint:errcheck

	// Protocol Step 1: Send attestation data (EK + AK) to server so it can generate proper challenge
	c.Logger.Debugf("Debug: Getting attestation data for challenge generation")
	ek, akParams, err := akManager.GetAttestationData()
	if err != nil {
		return "", fmt.Errorf("getting attestation data: %w", err)
	}
	c.Logger.Debugf("Debug: Got EK and AK attestation data")

	// Serialize EK to bytes using the existing encoding from tmp-helpers
	ekPEM, err := encodeEKToBytes(ek)
	if err != nil {
		return "", fmt.Errorf("encoding EK to bytes: %w", err)
	}

	// Serialize AK parameters to JSON bytes
	akBytes, err := json.Marshal(akParams)
	if err != nil {
		return "", fmt.Errorf("marshaling AK parameters: %w", err)
	}

	// Send attestation data to server as bytes
	attestationData := struct {
		EKBytes []byte `json:"ek_bytes"`
		AKBytes []byte `json:"ak_bytes"`
	}{
		EKBytes: ekPEM,
		AKBytes: akBytes,
	}

	c.Logger.Debugf("Debug: Sending attestation data to server")
	if err := conn.WriteJSON(attestationData); err != nil {
		return "", fmt.Errorf("sending attestation data: %w", err)
	}
	c.Logger.Debugf("Debug: Attestation data sent successfully")

	// Protocol Step 2: Wait for challenge response from server
	c.Logger.Debugf("Debug: Waiting for challenge from server")
	var challengeResp tpm.AttestationChallengeResponse
	if err := conn.ReadJSON(&challengeResp); err != nil {
		return "", fmt.Errorf("reading challenge from server: %w", err)
	}
	c.Logger.Debugf("Challenge received")

	// Protocol Step 3: Create proof request using AK Manager
	c.Logger.Debugf("Debug: Creating proof request from challenge response")
	proofReq, err := akManager.CreateProofRequest(&challengeResp)
	if err != nil {
		return "", fmt.Errorf("creating proof request: %w", err)
	}
	c.Logger.Debugf("Debug: Proof request created successfully")

	// Protocol Step 4: Send proof to server
	c.Logger.Debugf("Debug: Sending proof request to server")
	if err := conn.WriteJSON(proofReq); err != nil {
		return "", fmt.Errorf("sending proof request: %w", err)
	}
	c.Logger.Debugf("Proof request sent")

	// Protocol Step 5: Receive passphrase from server
	c.Logger.Debugf("Debug: Waiting for passphrase response")
	var proofResp tpm.ProofResponse
	if err := conn.ReadJSON(&proofResp); err != nil {
		return "", fmt.Errorf("reading passphrase response: %w", err)
	}
	c.Logger.Debugf("Passphrase received - Length: %d bytes", len(proofResp.Passphrase))

	// Check if we received an empty passphrase (indicates server error)
	if len(proofResp.Passphrase) == 0 {
		return "", fmt.Errorf("server returned empty passphrase, indicating an error occurred during attestation")
	}

	return string(proofResp.Passphrase), nil
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

// encodeEKToBytes encodes an EK to PEM bytes for transmission
func encodeEKToBytes(ek *attest.EK) ([]byte, error) {
	if ek.Certificate != nil {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: ek.Certificate.Raw,
		}
		return pem.EncodeToMemory(pemBlock), nil
	}

	// For EKs without certificates, marshal the public key
	pubBytes, err := x509.MarshalPKIXPublicKey(ek.Public)
	if err != nil {
		return nil, fmt.Errorf("marshaling EK public key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}
	return pem.EncodeToMemory(pemBlock), nil
}
