## Attestation Package

This package implements a clean, close-circle API for the kcrypt-challenger remote attestation flow. It separates client and server responsibilities and defines the wire messages used between them, so consumers can simply pass bytes from one step to the next and only check for errors in between.

Important: The client decides which PCRs to include/enroll/validate. The server validates according to its selective enrollment policy. Nonces are not used in this flow (sequential, authenticated channel).

### High-Level Flow

Client (node with TPM):
1) CreateInit → send to server
2) Receive AttestationChallenge
3) HandleChallenge → send AttestationProof to server

Server (kcrypt-challenger):
1) ParseInit
2) GenerateChallenge (EK+AK only; PCRs not needed here)
3) VerifyProof (secret + PCR quote signature verification + PCR consistency verification) → proceed with selective enrollment and passphrase release

### Wire Messages (owned by this package)
- AttestationInit: EK (PEM/DER), AK AttestationParameters, optional AK public
- AttestationChallenge: EncryptedCredential (no PCRs)
- AttestationProof: Secret (credential activation), PCRQuote (JSON with quote + selected PCR values)

### Client API
- NewRemoteAttestationClient(opts ...tpm.Option) (*RemoteAttestationClient, error)
- Close() error
- CreateInit() ([]byte, error)
- HandleChallenge(challengeBytes []byte) ([]byte, error)

Internally, the client uses transient AKs (no persistent AK storage). It sends EK + AK attestation data in AttestationInit, and later returns the secret and PCR quote in AttestationProof.

### Server API
- NewRemoteAttestationServer(attestator Attestator) *RemoteAttestationServer
- ParseInit(initBytes []byte) (ek *attest.EK, akParams *attest.AttestationParameters, err error)
- GenerateChallenge(initBytes []byte) (challengeBytes []byte, secret []byte, err error)
- VerifyProof(initBytes []byte, proofBytes []byte, expectedSecret []byte) (VerificationResult, error)
- IssuePassphrase(initBytes []byte, proofBytes []byte, expectedSecret []byte) ([]byte, error)

The server accepts AttestationInit, generates an EncryptedCredential (challenge) bound to EK+AK params (no PCRs), and later verifies the secret and the PCR quote signature using the AK public contained within the attestation parameters. The server also verifies that the provided PCR values are consistent with the TPM quote to ensure they are cryptographically bound to the quote. After verification, it delegates policy/enrollment to the injected Attestator and returns a passphrase or error.

### Selective Enrollment
This package does not implement enrollment. The server injects an Attestator which receives final verified attestation data and decides enrollment/validation and passphrase issuance. Typical policies (for reference):
- Empty value: accept any, update stored value (re-enrollment)
- Set value: enforce exact match (strict)
- Omitted: skip entirely

### Implementation Notes
- EK→AK binding is proven by successful credential activation (no separate AK certification step required).
- PCR quote structure contains both quote/signature and the actual selected PCR values.
- PCR quote signature is cryptographically verified using the AK public key to ensure PCR authenticity.
- PCR values are verified against the TPM quote digest to ensure they are cryptographically bound to the quote.
- This package owns message marshalling/unmarshalling so consumers don't need to manage encoding details.

### Attestator (Injected Policy)
The Attestator is provided by the consumer and is called after cryptographic verification succeeds. It decides selective enrollment/validation and returns the passphrase.

Interface (conceptual):

```
type Attestator interface {
    IssuePassphrase(ctx context.Context, req AttestationRequest) ([]byte, error)
}

type AttestationRequest struct {
    TPMHash string            // derived from EK (server-enrolled identity)
    PCRs    map[int][]byte    // client-selected PCRs from verified quote
    EKPEM   []byte            // optional: EK in PEM/DER for auditing/forensics
    // Optional: partition/volume metadata for policy, if the consumer passes it through
}
```

Notes:
- AK public is not passed to the Attestator. The library verifies the EK→AK→PCR chain and only then calls the Attestator with data relevant to policy (PCRs, TPM identity).

### Next Steps
- Implement Ginkgo tests that cover: init/challenge/proof happy path, invalid credentials, PCR set variations, selective enrollment behaviors.
- Refactor kcrypt-challenger to use this package end-to-end.
- Then clean up flow logic in tpm-helpers, keeping only low-level helpers.


