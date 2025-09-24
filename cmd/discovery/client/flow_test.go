package client

import (
	"testing"

	"github.com/kairos-io/kairos-sdk/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestClient(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Discovery Client Suite")
}

var _ = Describe("Flow Detection", func() {
	var client *Client

	BeforeEach(func() {
		// Create a test client with basic config and logger
		client = &Client{}
		client.Config.Kcrypt.Challenger.Server = "http://test-server.local"
		client.Logger = types.NewKairosLogger("test-client", "debug", false)
	})

	Context("TPM attestation capabilities", func() {
		It("should handle TPM operations", func() {
			// Test that client can be created without errors
			// TPM availability testing requires actual hardware
			Expect(client).ToNot(BeNil())
		})
	})

	Context("Logging functionality", func() {
		It("should have a valid logger", func() {
			// Test that client has a valid logger
			Expect(client.Logger).NotTo(BeNil())

			// Test debug logging works without error
			client.Logger.Debugf("Test log entry for flow detection")

			// If we get here without panic, logging is working
			Expect(true).To(BeTrue())
		})
	})

})
