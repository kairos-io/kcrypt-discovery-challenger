package attestation_test

import (
	"context"
	"encoding/json"

	"github.com/google/go-attestation/attest"
	. "github.com/kairos-io/kairos-challenger/pkg/attestation"
	tpmhelpers "github.com/kairos-io/tpm-helpers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type dummyAttestator struct{}

func (d *dummyAttestator) IssuePassphrase(ctx context.Context, req AttestationRequest) ([]byte, error) {
	return []byte("passphrase"), nil
}

var _ = Describe("Remote attestation end-to-end", func() {
	It("client and server roundtrip", func() {
		// Client: create init
		client, err := NewRemoteAttestationClient(tpmhelpers.Emulated, tpmhelpers.EmulatedHostSeed())
		Expect(err).ToNot(HaveOccurred())
		defer client.Close() //nolint:errcheck

		initBytes, err := client.CreateInit()
		Expect(err).ToNot(HaveOccurred())
		Expect(initBytes).ToNot(BeEmpty())

		// Server: parse init and generate challenge
		server := NewRemoteAttestationServer(&dummyAttestator{})
		challengeBytes, expectedSecret, err := server.GenerateChallenge(initBytes)
		Expect(err).ToNot(HaveOccurred())
		Expect(challengeBytes).ToNot(BeEmpty())
		Expect(expectedSecret).ToNot(BeEmpty())

		// Client: handle challenge with chosen PCRs
		proofBytes, err := client.HandleChallenge(challengeBytes, []int{0, 7, 11})
		Expect(err).ToNot(HaveOccurred())
		Expect(proofBytes).ToNot(BeEmpty())

		// Server: verify proof and issue passphrase
		vr, err := server.VerifyProof(initBytes, proofBytes, expectedSecret)
		Expect(err).ToNot(HaveOccurred())
		Expect(vr.PCRs).ToNot(BeNil())

		// Issue passphrase via attestator
		pass, err := server.IssuePassphrase(context.Background(), initBytes, proofBytes, expectedSecret)
		Expect(err).ToNot(HaveOccurred())
		Expect(pass).To(Equal([]byte("passphrase")))
	})

	It("methods validate input formats", func() {
		// malformed init
		server := NewRemoteAttestationServer(&dummyAttestator{})
		_, _, err := server.GenerateChallenge([]byte("not-json"))
		Expect(err).To(HaveOccurred())

		// client handle malformed challenge
		client, err := NewRemoteAttestationClient(tpmhelpers.Emulated, tpmhelpers.EmulatedHostSeed())
		Expect(err).ToNot(HaveOccurred())
		defer client.Close() //nolint:errcheck

		_, err = client.HandleChallenge([]byte("not-json"), []int{0})
		Expect(err).To(HaveOccurred())
	})

	It("server parse init decodes AK params", func() {
		client, err := NewRemoteAttestationClient(tpmhelpers.Emulated, tpmhelpers.EmulatedHostSeed())
		Expect(err).ToNot(HaveOccurred())
		defer client.Close() //nolint:errcheck

		initBytes, err := client.CreateInit()
		Expect(err).ToNot(HaveOccurred())

		ek, akParams, err := NewRemoteAttestationServer(&dummyAttestator{}).ParseInit(initBytes)
		Expect(err).ToNot(HaveOccurred())
		Expect(ek).ToNot(BeNil())
		Expect(akParams).ToNot(BeNil())

		// ensure akParams is valid
		var ap attest.AttestationParameters
		akParamsBytes, err := json.Marshal(akParams)
		Expect(err).ToNot(HaveOccurred())
		Expect(json.Unmarshal(akParamsBytes, &ap)).To(Succeed())
	})
})
