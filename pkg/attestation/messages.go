package attestation

import (
	"crypto/x509"
	"encoding/json"
)

// AttestationInit is sent by the client at the start of the flow.
// EKPublic is the SPKI-encoded public key (PKIX) of the EK.
// AKParams are the attestation parameters of the transient AK.
type AttestationInit struct {
	EKPublic []byte          `json:"ek_public"`
	AKParams json.RawMessage `json:"ak_params"` // marshaled attest.AttestationParameters
}

// AttestationChallenge is returned by the server: a JSON-encoded attest.EncryptedCredential
type AttestationChallenge struct {
	EncryptedCredential json.RawMessage `json:"challenge"`
}

// AttestationProof is returned by the client: secret + PCR quote payload
// PCRQuote is a JSON payload: { quote:{version,quote,signature}, pcrs:{index:value} }
type AttestationProof struct {
	Secret   []byte          `json:"secret"`
	PCRQuote json.RawMessage `json:"pcr_quote"`
}

// EncodePublicKeyToSPKI returns DER-encoded SubjectPublicKeyInfo for a public key
func EncodePublicKeyToSPKI(pub interface{}) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pub)
}
