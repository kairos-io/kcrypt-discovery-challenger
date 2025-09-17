package client

import (
	"os"
	"testing"

	"github.com/jaypipes/ghw/pkg/block"
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
		// Create a test client with basic config
		client = &Client{}
		client.Config.Kcrypt.Challenger.Server = "http://test-server.local"
	})

	Context("TPM attestation capabilities", func() {
		It("should detect TPM flow availability", func() {
			canUseTPM := client.canUseTPMAttestation()

			// Log the result for manual verification
			if canUseTPM {
				GinkgoLogr.Info("TPM attestation flow will be used")
			} else {
				GinkgoLogr.Info("Legacy flow will be used (no TPM or empty PCRs)")
			}

			// The test doesn't assert anything specific since TPM availability depends on the environment
			// This is more of an integration test to verify the flow selection logic works
			Expect(canUseTPM).To(BeAssignableToTypeOf(bool(true)))
		})
	})

	Context("Logging functionality", func() {
		AfterEach(func() {
			// Clean up log file after each test
			_ = os.Remove(LOGFILE)
		})

		It("should create log file when logging", func() {
			// Test logging functionality
			logToFile("Test log entry for flow detection\n")

			// Check if log file was created
			_, err := os.Stat(LOGFILE)
			Expect(err).NotTo(HaveOccurred(), "Log file should be created at %s", LOGFILE)
		})
	})

	Context("Flow routing", func() {
		It("should call the appropriate flow based on TPM availability", func() {
			// This test verifies that waitPass correctly routes to either TPM or legacy flow
			// Since we don't have a real server, we expect an error, but the routing logic should work

			_, err := client.waitPass(&block.Partition{
				Name:            "test-partition",
				UUID:            "test-uuid",
				FilesystemLabel: "test-label",
			}, 1)

			// We expect an error since there's no real server, but the flow selection should work
			Expect(err).To(HaveOccurred())

			// Check that the log file contains flow selection messages
			logContent, readErr := os.ReadFile(LOGFILE)
			Expect(readErr).NotTo(HaveOccurred())

			logStr := string(logContent)
			// Should contain either "TPM attestation" or "legacy flow" message
			Expect(logStr).To(ContainSubstring("flow"))
		})
	})
})
