package attestation

import (
	"encoding/json"

	"github.com/google/go-attestation/attest"
	tpmhelpers "github.com/kairos-io/tpm-helpers"
)

type RemoteAttestationClient struct {
	akm *tpmhelpers.AKManager
}

func NewRemoteAttestationClient(opts ...tpmhelpers.Option) (*RemoteAttestationClient, error) {
	akm, err := tpmhelpers.NewAKManager(opts...)
	if err != nil {
		return nil, err
	}
	return &RemoteAttestationClient{akm: akm}, nil
}

func (c *RemoteAttestationClient) Close() error {
	return c.akm.Close()
}

// CreateInit gathers EK and creates a transient AK, returning AttestationInit bytes
func (c *RemoteAttestationClient) CreateInit() ([]byte, error) {
	// Get attestation params of cached AK
	params, err := c.akm.AKParams()
	if err != nil {
		return nil, err
	}

	// Get EK
	ek, err := c.akm.GetEK()
	if err != nil {
		return nil, err
	}

	// Marshal AK params
	akParamsBytes, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}

	ekSPKI, err := EncodePublicKeyToSPKI(ek.Public)
	if err != nil {
		return nil, err
	}

	init := AttestationInit{
		EKPublic: ekSPKI,
		AKParams: akParamsBytes,
	}
	return json.Marshal(init)
}

// HandleChallenge takes an AttestationChallenge (bytes), activates credential, and returns AttestationProof bytes
// The client selects PCRs.
func (c *RemoteAttestationClient) HandleChallenge(challengeBytes []byte, pcrs []int) ([]byte, error) {
	var ch AttestationChallenge
	if err := json.Unmarshal(challengeBytes, &ch); err != nil {
		return nil, err
	}

	var ec struct{}
	if err := json.Unmarshal(ch.EncryptedCredential, &ec); err != nil {
		return nil, err
	}

	// Activate credential to get secret
	// Unmarshal EncryptedCredential into the right type
	var enc attest.EncryptedCredential
	if err := json.Unmarshal(ch.EncryptedCredential, &enc); err != nil {
		return nil, err
	}
	secret, err := c.akm.ActivateCredential(&enc)
	if err != nil {
		return nil, err
	}

	// Generate PCR quote
	pcrQuote, err := c.akm.GeneratePCRQuote(pcrs)
	if err != nil {
		return nil, err
	}

	proof := AttestationProof{Secret: secret, PCRQuote: pcrQuote}
	return json.Marshal(proof)
}
