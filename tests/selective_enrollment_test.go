package e2e_test

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/spectrocloud/peg/matcher"
)

// These tests focus on selective enrollment scenarios and VM reuse optimization
// Instead of spinning up a new VM for each test case, we reuse VMs across
// sequential scenarios to reduce test execution time.

var _ = Describe("Selective Enrollment E2E Tests", func() {
	var config string
	var vmOpts VMOptions
	var expectedInstallationSuccess bool
	var testVM VM
	var tpmHash string

	// VM lifecycle management for reuse optimization
	var vmInitialized bool

	BeforeEach(func() {
		expectedInstallationSuccess = true
		vmOpts = DefaultVMOptions()
		vmInitialized = false
	})

	AfterEach(func() {
		if vmInitialized {
			testVM.GatherLog("/run/immucore/immucore.log")
		}
	})

	// Local helper functions using common suite functions
	ensureVMRunning := func() {
		if !vmInitialized {
			By("Starting VM for selective enrollment tests")
			_, testVM = startVM(vmOpts)
			fmt.Printf("\nselective enrollment VM.StateDir = %+v\n", testVM.StateDir)
			testVM.EventuallyConnects(1200)
			vmInitialized = true
		}
	}

	installKairosWithConfig := func(config string) {
		installKairosWithConfigAdvanced(testVM, config, expectedInstallationSuccess)
	}

	// Cleanup VM at the very end
	var _ = AfterSuite(func() {
		if vmInitialized {
			cleanupVM(testVM)
		}
	})

	When("Testing Pure TOFU Enrollment Flow", Label("remote-tofu"), func() {
		It("should perform complete TOFU enrollment and subsequent successful authentications", func() {
			ensureVMRunning()

			// Step 1: Get TPM hash but don't create any SealedVolume (pure TOFU)
			tpmHash = getTPMHash(testVM)

			// Ensure no pre-existing SealedVolume
			deleteSealedVolume(tpmHash)

			// Step 2: Configure Kairos for remote KMS without pre-created SealedVolume
			config = fmt.Sprintf(`#cloud-config

hostname: metal-{{ trunc 4 .MachineID }}
users:
- name: kairos
  passwd: kairos

install:
  encrypted_partitions:
  - COS_PERSISTENT
  grub_options:
    extra_cmdline: "rd.neednet=1"
  reboot: false

kcrypt:
  challenger:
    challenger_server: "http://%s"
`, os.Getenv("KMS_ADDRESS"))

			installKairosWithConfig(config)
			rebootAndConnect(testVM)
			verifyEncryptedPartition(testVM)

			// Step 3: Verify SealedVolume was auto-created with TOFU enrollment
			By("Verifying SealedVolume was auto-created with attestation data")
			Eventually(func() bool {
				cmd := exec.Command("kubectl", "get", "sealedvolume", tpmHash, "-o", "yaml")
				out, err := cmd.CombinedOutput()
				if err != nil {
					return false
				}
				// Check that attestation data was populated (not empty)
				return strings.Contains(string(out), "attestation:") &&
					strings.Contains(string(out), "ekPublicKey:") &&
					strings.Contains(string(out), "akPublicKey:")
			}, 30*time.Second, 5*time.Second).Should(BeTrue())

			// Step 4: Verify secret was created
			By("Verifying encryption secret was auto-generated")
			Eventually(func() bool {
				return secretExists(fmt.Sprintf("%s-cos-persistent", tpmHash))
			}, 30*time.Second, 5*time.Second).Should(BeTrue())

			// Step 5: Test subsequent authentication works
			By("Testing subsequent authentication with learned attestation data")
			rebootAndConnect(testVM)
			verifyEncryptedPartition(testVM)

			cleanupTestResources(tpmHash)
		})
	})

	When("Testing Quarantine Management", Label("remote-quarantine"), func() {
		It("should handle quarantine, rejection, and recovery flows using the same VM", func() {
			ensureVMRunning()

			// Step 1: Initial enrollment
			tpmHash = getTPMHash(testVM)
			deleteSealedVolume(tpmHash) // Ensure clean state

			// Create SealedVolume for TOFU enrollment
			createSealedVolumeWithAttestation(tpmHash, nil)

			config = fmt.Sprintf(`#cloud-config

hostname: metal-{{ trunc 4 .MachineID }}
users:
- name: kairos
  passwd: kairos

install:
  encrypted_partitions:
  - COS_PERSISTENT
  grub_options:
    extra_cmdline: "rd.neednet=1"
  reboot: false

kcrypt:
  challenger:
    challenger_server: "http://%s"
`, os.Getenv("KMS_ADDRESS"))

			installKairosWithConfig(config)
			rebootAndConnect(testVM)
			verifyEncryptedPartition(testVM)

			// Step 2: Quarantine the TPM
			quarantineTPM(tpmHash)

			// Give some time for the change to propagate
			time.Sleep(5 * time.Second)

			// Step 3: Verify quarantined TPM is rejected via CLI (no risky reboot)
			By("Testing that quarantined TPM is rejected via CLI")

			// Give some time for quarantine to propagate
			time.Sleep(5 * time.Second)

			// Should fail to retrieve passphrase when quarantined
			expectPassphraseRetrieval(testVM, "COS_PERSISTENT", false)

			// Step 4: Test recovery by unquarantining
			By("Testing recovery by unquarantining TPM")
			unquarantineTPM(tpmHash)

			// Give some time for the change to propagate
			time.Sleep(5 * time.Second)

			// Should now be able to retrieve passphrase again
			expectPassphraseRetrieval(testVM, "COS_PERSISTENT", true)

			cleanupTestResources(tpmHash)
		})
	})

	When("Testing PCR Management Scenarios", Label("remote-pcr-mgmt"), func() {
		It("should handle PCR re-enrollment, omission, and mixed states using the same VM", func() {
			ensureVMRunning()

			// Step 1: Initial enrollment with specific PCR enforcement
			tpmHash = getTPMHash(testVM)
			deleteSealedVolume(tpmHash)

			// Create SealedVolume with specific PCR values enforced
			attestationConfig := map[string]interface{}{
				"pcrValues": map[string]string{
					"0": "specific-pcr0-value", // Will be enforced
					"7": "",                    // Will be re-enrolled
					// PCR 11 omitted - will be ignored
				},
			}
			createSealedVolumeWithAttestation(tpmHash, attestationConfig)

			config = fmt.Sprintf(`#cloud-config

hostname: metal-{{ trunc 4 .MachineID }}
users:
- name: kairos
  passwd: kairos

install:
  encrypted_partitions:
  - COS_PERSISTENT
  grub_options:
    extra_cmdline: "rd.neednet=1"
  reboot: false

kcrypt:
  challenger:
    challenger_server: "http://%s"
`, os.Getenv("KMS_ADDRESS"))

			installKairosWithConfig(config)
			rebootAndConnect(testVM)
			verifyEncryptedPartition(testVM)

			// Step 2: Verify PCR 7 was re-enrolled (updated from empty to actual value)
			By("Verifying PCR 7 was re-enrolled with actual value")
			Eventually(func() bool {
				cmd := exec.Command("kubectl", "get", "sealedvolume", tpmHash, "-o", "yaml")
				out, err := cmd.CombinedOutput()
				if err != nil {
					return false
				}
				// PCR 7 should now have a non-empty value
				return strings.Contains(string(out), "\"7\":") &&
					!strings.Contains(string(out), "\"7\": \"\"")
			}, 30*time.Second, 5*time.Second).Should(BeTrue())

			// Step 3: Test PCR enforcement by changing enforced PCR (should fail via CLI)
			By("Testing PCR enforcement by modifying enforced PCR 0")
			updateSealedVolumeAttestation(tpmHash, "pcrValues.pcrs.0", "wrong-pcr0-value")

			time.Sleep(5 * time.Second)

			// Should fail to retrieve passphrase with wrong PCR value
			expectPassphraseRetrieval(testVM, "COS_PERSISTENT", false)

			// Step 4: Test PCR re-enrollment by setting to empty
			By("Testing PCR re-enrollment by setting PCR 0 to empty")
			updateSealedVolumeAttestation(tpmHash, "pcrValues.pcrs.0", "")

			time.Sleep(5 * time.Second)

			// Should now re-enroll and work via CLI
			expectPassphraseRetrieval(testVM, "COS_PERSISTENT", true)

			// Step 5: Verify PCR 0 was re-enrolled with new value
			By("Verifying PCR 0 was re-enrolled with current value")
			Eventually(func() bool {
				cmd := exec.Command("kubectl", "get", "sealedvolume", tpmHash, "-o", "yaml")
				out, err := cmd.CombinedOutput()
				if err != nil {
					return false
				}
				// PCR 0 should now have a new non-empty value
				return strings.Contains(string(out), "\"0\":") &&
					!strings.Contains(string(out), "\"0\": \"\"") &&
					!strings.Contains(string(out), "\"0\": \"wrong-pcr0-value\"")
			}, 30*time.Second, 5*time.Second).Should(BeTrue())

			cleanupTestResources(tpmHash)
		})
	})

	When("Testing AK Management", Label("remote-ak-mgmt"), func() {
		It("should handle AK re-enrollment and enforcement using the same VM", func() {
			ensureVMRunning()

			// Step 1: Initial enrollment with AK re-enrollment mode
			tpmHash = getTPMHash(testVM)
			deleteSealedVolume(tpmHash)

			// Create SealedVolume with empty AK (re-enrollment mode)
			attestationConfig := map[string]interface{}{
				"akPublicKey": "", // Will be re-enrolled
				"ekPublicKey": "", // Will be re-enrolled
			}
			createSealedVolumeWithAttestation(tpmHash, attestationConfig)

			config = fmt.Sprintf(`#cloud-config

hostname: metal-{{ trunc 4 .MachineID }}
users:
- name: kairos
  passwd: kairos

install:
  encrypted_partitions:
  - COS_PERSISTENT
  grub_options:
    extra_cmdline: "rd.neednet=1"
  reboot: false

kcrypt:
  challenger:
    challenger_server: "http://%s"
`, os.Getenv("KMS_ADDRESS"))

			installKairosWithConfig(config)
			rebootAndConnect(testVM)
			verifyEncryptedPartition(testVM)

			// Step 2: Verify AK and EK were re-enrolled
			By("Verifying AK and EK were re-enrolled with actual values")
			var learnedAK, learnedEK string
			Eventually(func() bool {
				cmd := exec.Command("kubectl", "get", "sealedvolume", tpmHash, "-o", "yaml")
				out, err := cmd.CombinedOutput()
				if err != nil {
					return false
				}

				// Extract learned AK and EK for later enforcement test
				lines := strings.Split(string(out), "\n")
				for _, line := range lines {
					if strings.Contains(line, "akPublicKey:") && !strings.Contains(line, "akPublicKey: \"\"") {
						parts := strings.Split(line, "akPublicKey:")
						if len(parts) > 1 {
							learnedAK = strings.TrimSpace(strings.Trim(parts[1], "\""))
						}
					}
					if strings.Contains(line, "ekPublicKey:") && !strings.Contains(line, "ekPublicKey: \"\"") {
						parts := strings.Split(line, "ekPublicKey:")
						if len(parts) > 1 {
							learnedEK = strings.TrimSpace(strings.Trim(parts[1], "\""))
						}
					}
				}

				return learnedAK != "" && learnedEK != ""
			}, 30*time.Second, 5*time.Second).Should(BeTrue())

			// Step 3: Test AK enforcement by setting wrong AK
			By("Testing AK enforcement by setting wrong AK value")
			updateSealedVolumeAttestation(tpmHash, "akPublicKey", "wrong-ak-value")

			time.Sleep(5 * time.Second)

			// Should fail to retrieve passphrase with wrong AK
			expectPassphraseRetrieval(testVM, "COS_PERSISTENT", false)

			// Step 4: Restore correct AK and verify it works via CLI
			By("Restoring correct AK and verifying authentication works")
			updateSealedVolumeAttestation(tpmHash, "akPublicKey", learnedAK)

			time.Sleep(5 * time.Second)

			// Should now work with correct AK
			expectPassphraseRetrieval(testVM, "COS_PERSISTENT", true)

			cleanupTestResources(tpmHash)
		})
	})

	When("Testing Secret Reuse Scenarios", Label("remote-secret-reuse"), func() {
		It("should reuse existing secrets when SealedVolume is recreated", func() {
			ensureVMRunning()

			// Step 1: Initial enrollment to create secret
			tpmHash = getTPMHash(testVM)
			deleteSealedVolume(tpmHash)

			createSealedVolumeWithAttestation(tpmHash, nil)

			config = fmt.Sprintf(`#cloud-config

hostname: metal-{{ trunc 4 .MachineID }}
users:
- name: kairos
  passwd: kairos

install:
  encrypted_partitions:
  - COS_PERSISTENT
  grub_options:
    extra_cmdline: "rd.neednet=1"
  reboot: false

kcrypt:
  challenger:
    challenger_server: "http://%s"
`, os.Getenv("KMS_ADDRESS"))

			installKairosWithConfig(config)
			rebootAndConnect(testVM)
			verifyEncryptedPartition(testVM)

			// Step 2: Get the generated secret
			secretName := fmt.Sprintf("%s-cos-persistent", tpmHash)
			Eventually(func() bool {
				return secretExists(secretName)
			}, 30*time.Second, 5*time.Second).Should(BeTrue())

			// Get secret data for comparison
			cmd := exec.Command("kubectl", "get", "secret", secretName, "-o", "yaml")
			originalSecretData, err := cmd.CombinedOutput()
			Expect(err).ToNot(HaveOccurred())

			// Step 3: Delete SealedVolume but keep secret
			deleteSealedVolume(tpmHash)

			// Verify secret still exists
			Expect(secretExists(secretName)).To(BeTrue())

			// Step 4: Recreate SealedVolume and verify secret reuse
			By("Recreating SealedVolume and verifying secret reuse")
			createSealedVolumeWithAttestation(tpmHash, nil)

			// Should reuse existing secret
			rebootAndConnect(testVM)
			verifyEncryptedPartition(testVM)

			// Step 5: Verify the same secret is being used
			cmd = exec.Command("kubectl", "get", "secret", secretName, "-o", "yaml")
			newSecretData, err := cmd.CombinedOutput()
			Expect(err).ToNot(HaveOccurred())

			// The secret data should be identical (reused, not regenerated)
			Expect(string(newSecretData)).To(Equal(string(originalSecretData)))

			cleanupTestResources(tpmHash)
		})
	})

	When("Testing Error Handling and Edge Cases", Label("remote-edge-cases"), func() {
		It("should handle various error conditions properly", func() {
			ensureVMRunning()

			// Step 1: Test invalid TPM hash rejection
			By("Testing invalid TPM hash rejection")
			invalidHash := "invalid-tpm-hash-12345"
			createSealedVolumeWithAttestation(invalidHash, nil)

			config = fmt.Sprintf(`#cloud-config

hostname: metal-{{ trunc 4 .MachineID }}
users:
- name: kairos
  passwd: kairos

install:
  encrypted_partitions:
  - COS_PERSISTENT
  grub_options:
    extra_cmdline: "rd.neednet=1"
  reboot: false

kcrypt:
  challenger:
    challenger_server: "http://%s"
`, os.Getenv("KMS_ADDRESS"))

			installKairosWithConfig(config)

			// Should fail due to TPM hash mismatch (test via CLI, no risky reboot)
			expectPassphraseRetrieval(testVM, "COS_PERSISTENT", false)

			// Cleanup invalid SealedVolume
			deleteSealedVolume(invalidHash)

			// Step 2: Test with correct TPM hash to verify system works
			tpmHash = getTPMHash(testVM)
			createSealedVolumeWithAttestation(tpmHash, nil)

			// Test with correct hash should work
			expectPassphraseRetrieval(testVM, "COS_PERSISTENT", true)

			cleanupTestResources(tpmHash)
		})
	})
})
