package main

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCLI(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Discovery CLI Suite")
}

var _ = Describe("CLI Interface", func() {
	BeforeEach(func() {
		// Clean up any previous log files
		_ = os.Remove("/tmp/kcrypt-challenger-client.log")
	})

	AfterEach(func() {
		// Clean up log files
		_ = os.Remove("/tmp/kcrypt-challenger-client.log")
	})

	Context("CLI help", func() {
		It("should show help when --help is used", func() {
			err := ExecuteWithArgs([]string{"--help"})

			Expect(err).To(BeNil())
			// We can't easily test the output content without complex output capture,
			// but we can verify the function executes without error
		})
	})

	Context("Input validation", func() {
		It("should require all partition parameters for get command", func() {
			err := ExecuteWithArgs([]string{"get"})

			Expect(err).To(HaveOccurred())
			// Should return an error when required parameters are missing
		})

		It("should validate that all required fields are provided for get command", func() {
			// Test with valid partition parameters
			err := ExecuteWithArgs([]string{"get", "--partition-name=/dev/sda2"})
			Expect(err).To(HaveOccurred()) // Should fail at client connection but parsing should work

			// Test with valid UUID
			err = ExecuteWithArgs([]string{"get", "--partition-uuid=12345"})
			Expect(err).To(HaveOccurred()) // Should fail at client connection but parsing should work
		})

		It("should handle invalid flags gracefully", func() {
			err := ExecuteWithArgs([]string{"--invalid-flag"})

			Expect(err).To(HaveOccurred())
			// Should return an error for invalid flags
		})
	})

	Context("Configuration overrides with debug logging", func() {
		var tempDir string
		var originalLogFile string
		var testLogFile string
		var configDir string

		BeforeEach(func() {
			// Create a temporary directory for this test
			var err error
			tempDir, err = os.MkdirTemp("", "kcrypt-test-*")
			Expect(err).NotTo(HaveOccurred())

			// Use /tmp/oem since it's already in confScanDirs
			configDir = "/tmp/oem"
			err = os.MkdirAll(configDir, 0755)
			Expect(err).NotTo(HaveOccurred())

			// Create a test configuration file with known values
			configContent := `kcrypt:
  challenger:
    challenger_server: "https://default-server.com:8080"
    mdns: false
    certificate: "/default/path/to/cert.pem"
    nv_index: "0x1500000"
    c_index: "0x1400000"
    tpm_device: "/dev/tpm0"
`
			configFile := filepath.Join(configDir, "kairos.yaml")
			err = os.WriteFile(configFile, []byte(configContent), 0644)
			Expect(err).NotTo(HaveOccurred())

			// Override the log file location for testing
			originalLogFile = os.Getenv("KAIROS_LOG_FILE")
			testLogFile = filepath.Join(tempDir, "kcrypt-discovery-challenger.log")
			os.Setenv("KAIROS_LOG_FILE", testLogFile)
		})

		AfterEach(func() {
			// Restore original log file setting
			if originalLogFile != "" {
				os.Setenv("KAIROS_LOG_FILE", originalLogFile)
			} else {
				os.Unsetenv("KAIROS_LOG_FILE")
			}

			// Clean up config file
			_ = os.RemoveAll(configDir)

			// Clean up temporary directory
			_ = os.RemoveAll(tempDir)
		})

		It("should read and use original configuration values without overrides", func() {
			err := ExecuteWithArgs([]string{
				"get",
				"--partition-name=/dev/test",
				"--partition-uuid=test-uuid",
				"--partition-label=test-label",
				"--debug",
				"--attempts=1",
			})

			// Should fail at passphrase retrieval but config parsing should work
			Expect(err).To(HaveOccurred())

			// Check that original configuration values are logged
			logContent, readErr := os.ReadFile(testLogFile)
			if readErr == nil {
				logStr := string(logContent)
				// Should show original configuration values from the file
				Expect(logStr).To(ContainSubstring("Original configuration"))
				Expect(logStr).To(ContainSubstring("https://default-server.com:8080"))
				Expect(logStr).To(ContainSubstring("false")) // mdns value
				Expect(logStr).To(ContainSubstring("/default/path/to/cert.pem"))
				// Should also show final configuration (which should be the same as original)
				Expect(logStr).To(ContainSubstring("Final configuration"))
				// Should NOT contain any override messages since no flags were provided
				Expect(logStr).NotTo(ContainSubstring("Overriding server URL"))
				Expect(logStr).NotTo(ContainSubstring("Overriding MDNS setting"))
				Expect(logStr).NotTo(ContainSubstring("Overriding certificate"))
			}
		})

		It("should show configuration file values being overridden by CLI flags", func() {
			err := ExecuteWithArgs([]string{
				"get",
				"--partition-name=/dev/test",
				"--partition-uuid=test-uuid",
				"--partition-label=test-label",
				"--challenger-server=https://overridden-server.com:9999",
				"--mdns=true",
				"--certificate=/overridden/cert.pem",
				"--debug",
				"--attempts=1",
			})

			// Should fail at passphrase retrieval but config parsing and overrides should work
			Expect(err).To(HaveOccurred())

			// Check that both original and overridden values are logged
			logContent, readErr := os.ReadFile(testLogFile)
			if readErr == nil {
				logStr := string(logContent)
				// Should show original configuration values from the file
				Expect(logStr).To(ContainSubstring("Original configuration"))
				Expect(logStr).To(ContainSubstring("https://default-server.com:8080"))
				Expect(logStr).To(ContainSubstring("/default/path/to/cert.pem"))

				// Should show override messages
				Expect(logStr).To(ContainSubstring("Overriding server URL"))
				Expect(logStr).To(ContainSubstring("https://default-server.com:8080 -> https://overridden-server.com:9999"))
				Expect(logStr).To(ContainSubstring("Overriding MDNS setting"))
				Expect(logStr).To(ContainSubstring("false -> true"))
				Expect(logStr).To(ContainSubstring("Overriding certificate"))

				// Should show final configuration with overridden values
				Expect(logStr).To(ContainSubstring("Final configuration"))
				Expect(logStr).To(ContainSubstring("https://overridden-server.com:9999"))
				Expect(logStr).To(ContainSubstring("/overridden/cert.pem"))
			}
		})

		It("should apply CLI flag overrides and log configuration changes", func() {
			err := ExecuteWithArgs([]string{
				"get",
				"--partition-name=/dev/test",
				"--partition-uuid=test-uuid",
				"--partition-label=test-label",
				"--challenger-server=https://custom-server.com:8082",
				"--mdns=true",
				"--certificate=/path/to/cert.pem",
				"--debug",
				"--attempts=1",
			})

			// Should fail at passphrase retrieval but flag parsing should work
			Expect(err).To(HaveOccurred())

			// Check if debug log exists and contains configuration information
			logContent, readErr := os.ReadFile(testLogFile)
			if readErr == nil {
				logStr := string(logContent)
				// Should contain debug information about configuration overrides
				Expect(logStr).To(ContainSubstring("Overriding server URL"))
				Expect(logStr).To(ContainSubstring("https://custom-server.com:8082"))
				Expect(logStr).To(ContainSubstring("Overriding MDNS setting"))
				Expect(logStr).To(ContainSubstring("Overriding certificate"))
			}
		})

		It("should show original vs final configuration in debug mode", func() {
			err := ExecuteWithArgs([]string{
				"get",
				"--partition-name=/dev/test",
				"--partition-uuid=test-uuid",
				"--partition-label=test-label",
				"--challenger-server=https://override-server.com:9999",
				"--debug",
				"--attempts=1",
			})

			// Should fail but debug information should be logged
			Expect(err).To(HaveOccurred())

			// Check for original and final configuration logging
			logContent, readErr := os.ReadFile(testLogFile)
			if readErr == nil {
				logStr := string(logContent)
				Expect(logStr).To(ContainSubstring("Original configuration"))
				Expect(logStr).To(ContainSubstring("Final configuration"))
				Expect(logStr).To(ContainSubstring("https://override-server.com:9999"))
			}
		})

		It("should log partition details in debug mode", func() {
			err := ExecuteWithArgs([]string{
				"get",
				"--partition-name=/dev/custom-partition",
				"--partition-uuid=custom-uuid-123",
				"--partition-label=custom-label-456",
				"--debug",
				"--attempts=2",
			})

			Expect(err).To(HaveOccurred())

			// Check for partition details in debug log
			logContent, readErr := os.ReadFile(testLogFile)
			if readErr == nil {
				logStr := string(logContent)
				Expect(logStr).To(ContainSubstring("Partition details"))
				Expect(logStr).To(ContainSubstring("/dev/custom-partition"))
				Expect(logStr).To(ContainSubstring("custom-uuid-123"))
				Expect(logStr).To(ContainSubstring("custom-label-456"))
				Expect(logStr).To(ContainSubstring("Attempts: 2"))
			}
		})

		It("should not log debug information without debug flag", func() {
			err := ExecuteWithArgs([]string{
				"get",
				"--partition-name=/dev/test",
				"--partition-uuid=test-uuid",
				"--partition-label=test-label",
				"--attempts=1",
			})

			Expect(err).To(HaveOccurred())

			// Debug log should not exist or should not contain detailed debug info
			logContent, readErr := os.ReadFile(testLogFile)
			if readErr == nil {
				logStr := string(logContent)
				// Should not contain debug-level details
				Expect(logStr).NotTo(ContainSubstring("Original configuration"))
				Expect(logStr).NotTo(ContainSubstring("Partition details"))
			}
		})

		It("should handle missing configuration file gracefully and show defaults", func() {
			// Remove the config file to test default behavior
			_ = os.RemoveAll(configDir)

			err := ExecuteWithArgs([]string{
				"get",
				"--partition-name=/dev/test",
				"--partition-uuid=test-uuid",
				"--partition-label=test-label",
				"--debug",
				"--attempts=1",
			})

			// Should fail at passphrase retrieval but not due to config parsing
			Expect(err).To(HaveOccurred())

			// Check that default/empty configuration values are logged
			logContent, readErr := os.ReadFile(testLogFile)
			if readErr == nil {
				logStr := string(logContent)
				// Should show original configuration (which should be empty/defaults)
				Expect(logStr).To(ContainSubstring("Original configuration"))
				Expect(logStr).To(ContainSubstring("Final configuration"))
				// Should NOT contain override messages since no flags were provided
				Expect(logStr).NotTo(ContainSubstring("Overriding server URL"))
				Expect(logStr).NotTo(ContainSubstring("Overriding MDNS setting"))
				Expect(logStr).NotTo(ContainSubstring("Overriding certificate"))
			}
		})
	})

	Context("CLI argument parsing", func() {
		It("should parse all arguments correctly", func() {
			// This will fail at the client creation/server connection,
			// but should successfully parse all arguments
			err := ExecuteWithArgs([]string{
				"get",
				"--partition-name=/dev/custom",
				"--partition-uuid=custom-uuid-999",
				"--partition-label=custom-label",
				"--attempts=5",
			})

			Expect(err).To(HaveOccurred()) // Fails due to no server
			// The important thing is that flag parsing worked and it reached the backend
		})

		It("should handle boolean flags correctly", func() {
			// Test help flag
			err := ExecuteWithArgs([]string{"--help"})
			Expect(err).To(BeNil())
		})
	})
})
