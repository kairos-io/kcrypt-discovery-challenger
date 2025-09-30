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

// Advanced scenarios that test complex operational workflows,
// performance aspects, and edge cases

var _ = Describe("Remote Attestation E2E Tests", Label("remote-complete-workflow"), func() {
	var config string
	var vmOpts VMOptions
	var expectedInstallationSuccess bool
	var testVM VM
	var tpmHash string

	BeforeEach(func() {
		expectedInstallationSuccess = true
		vmOpts = DefaultVMOptions()
		_, testVM = startVM(vmOpts)
		testVM.EventuallyConnects(1200)
	})

	AfterEach(func() {
		cleanupVM(testVM)
		// Clean up test resources if tpmHash was set
		if tpmHash != "" {
			cleanupTestResources(tpmHash)
		}
	})

	installKairosWithConfig := func(config string) {
		installKairosWithConfigAdvanced(testVM, config, expectedInstallationSuccess)
	}

	It("should perform TOFU enrollment, quarantine testing, PCR management, AK management, error handling, secret reuse, and multi-partition support", func() {
		tpmHash = getTPMHash(testVM)

		deleteSealedVolume(tpmHash)

		config = fmt.Sprintf(`#cloud-config

hostname: metal-{{ trunc 4 .MachineID }}
users:
- name: kairos
passwd: kairos

install:
  encrypted_partitions:
  - COS_PERSISTENT
  - COS_OEM
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

		// Verify both partitions are encrypted
		By("Verifying both partitions are encrypted")
		out, err := testVM.Sudo("blkid")
		Expect(err).ToNot(HaveOccurred(), out)
		Expect(out).To(MatchRegexp("TYPE=\"crypto_LUKS\" PARTLABEL=\"persistent\""), out)
		Expect(out).To(MatchRegexp("TYPE=\"crypto_LUKS\" PARTLABEL=\"oem\""), out)

		By("Verifying SealedVolume was auto-created with attestation data")
		Eventually(func() bool {
			sealedVolumeName := getSealedVolumeName(tpmHash)
			cmd := exec.Command("kubectl", "get", "sealedvolume", sealedVolumeName, "-o", "yaml")
			out, err := cmd.CombinedOutput()
			if err != nil {
				return false
			}
			// Check that attestation data was populated (not empty)
			return strings.Contains(string(out), "attestation:") &&
				strings.Contains(string(out), "ekPublicKey:") &&
				strings.Contains(string(out), "akPublicKey:")
		}, 30*time.Second, 5*time.Second).Should(BeTrue())

		By("Verifying encryption secrets were auto-generated for both partitions")
		Eventually(func() bool {
			sealedVolumeName := getSealedVolumeName(tpmHash)
			return secretExists(fmt.Sprintf("%s-cos-persistent", sealedVolumeName)) &&
				secretExists(fmt.Sprintf("%s-cos-oem", sealedVolumeName))
		}, 30*time.Second, 5*time.Second).Should(BeTrue())

		By("Testing subsequent authentication with learned attestation data")
		rebootAndConnect(testVM)
		verifyEncryptedPartition(testVM)

		By("quarantining the TPM")
		quarantineTPM(tpmHash)

		By("Testing that quarantined TPM is rejected via CLI for both partitions")
		expectPassphraseRetrieval(testVM, "COS_PERSISTENT", false)
		expectPassphraseRetrieval(testVM, "COS_OEM", false)

		By("Testing recovery by unquarantining TPM")
		unquarantineTPM(tpmHash)

		expectPassphraseRetrieval(testVM, "COS_PERSISTENT", true)
		expectPassphraseRetrieval(testVM, "COS_OEM", true)

		// Continue with PCR and AK Management testing
		By("Testing PCR re-enrollment by setting PCR 0 to wrong value")
		updateSealedVolumeAttestation(tpmHash, "pcrValues.pcrs.0", "wrong-pcr0-value")

		By("checking that the passphrase retrieval fails with wrong PCR for both partitions")
		expectPassphraseRetrieval(testVM, "COS_PERSISTENT", false)
		expectPassphraseRetrieval(testVM, "COS_OEM", false)

		By("setting PCR 0 to an empty value (re-enrollment mode)")
		updateSealedVolumeAttestation(tpmHash, "pcrValues.pcrs.0", "")

		By("checking that the passphrase retrieval works after PCR re-enrollment for both partitions")
		expectPassphraseRetrieval(testVM, "COS_PERSISTENT", true)
		expectPassphraseRetrieval(testVM, "COS_OEM", true)

		By("Verifying PCR 0 was re-enrolled with current value")
		Eventually(func() bool {
			sealedVolumeName := getSealedVolumeName(tpmHash)
			cmd := exec.Command("kubectl", "get", "sealedvolume", sealedVolumeName, "-o", "yaml")
			out, err := cmd.CombinedOutput()
			if err != nil {
				return false
			}
			// PCR 0 should now have a new non-empty value
			return strings.Contains(string(out), "\"0\":") &&
				!strings.Contains(string(out), "\"0\": \"\"") &&
				!strings.Contains(string(out), "\"0\": \"wrong-pcr0-value\"")
		}, 30*time.Second, 5*time.Second).Should(BeTrue())

		// Continue with EK Management testing (transient AK approach)
		By("Testing EK re-enrollment by setting EK to empty")
		updateSealedVolumeAttestation(tpmHash, "ekPublicKey", "")

		By("Verifying EK was re-enrolled with actual value")
		var learnedEK string
		Eventually(func() bool {
			sealedVolumeName := getSealedVolumeName(tpmHash)
			cmd := exec.Command("kubectl", "get", "sealedvolume", sealedVolumeName, "-o", "yaml")
			out, err := cmd.CombinedOutput()
			if err != nil {
				return false
			}

			// Extract learned EK for later enforcement test
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				if strings.Contains(line, "ekPublicKey:") && !strings.Contains(line, "ekPublicKey: \"\"") {
					parts := strings.Split(line, "ekPublicKey:")
					if len(parts) > 1 {
						learnedEK = strings.TrimSpace(strings.Trim(parts[1], "\""))
					}
				}
			}

			return learnedEK != ""
		}, 30*time.Second, 5*time.Second).Should(BeTrue())

		// Test EK enforcement by setting wrong EK
		By("Testing EK enforcement by setting wrong EK value")
		updateSealedVolumeAttestation(tpmHash, "ekPublicKey", "wrong-ek-value")

		time.Sleep(5 * time.Second)

		// Should fail to retrieve passphrase with wrong EK for both partitions
		expectPassphraseRetrieval(testVM, "COS_PERSISTENT", false)
		expectPassphraseRetrieval(testVM, "COS_OEM", false)

		// Restore correct EK and verify it works via CLI
		By("Restoring correct EK and verifying authentication works for both partitions")
		updateSealedVolumeAttestation(tpmHash, "ekPublicKey", learnedEK)

		time.Sleep(5 * time.Second)

		// Should now work with correct EK for both partitions
		expectPassphraseRetrieval(testVM, "COS_PERSISTENT", true)
		expectPassphraseRetrieval(testVM, "COS_OEM", true)

		// Continue with Error Handling testing
		By("Testing invalid TPM hash rejection")
		invalidHash := "invalid-tpm-hash-12345"
		createSealedVolumeWithAttestation(invalidHash, nil)

		// Should fail due to TPM hash mismatch for both partitions (test via CLI, no risky reboot)
		expectPassphraseRetrieval(testVM, "COS_PERSISTENT", false)
		expectPassphraseRetrieval(testVM, "COS_OEM", false)

		// Cleanup invalid SealedVolume
		deleteSealedVolume(invalidHash)

		// Test with correct TPM hash to verify system still works for both partitions
		By("Verifying system still works with correct TPM hash for both partitions")
		// The original SealedVolume should still exist and work
		expectPassphraseRetrieval(testVM, "COS_PERSISTENT", true)
		expectPassphraseRetrieval(testVM, "COS_OEM", true)

		// Continue with Secret Reuse testing
		By("Testing secret reuse when SealedVolume is recreated for both partitions")
		sealedVolumeName := getSealedVolumeName(tpmHash)
		persistentSecretName := fmt.Sprintf("%s-cos-persistent", sealedVolumeName)
		oemSecretName := fmt.Sprintf("%s-cos-oem", sealedVolumeName)

		// Get secret data for comparison for both partitions
		cmd := exec.Command("kubectl", "get", "secret", persistentSecretName, "-o", "yaml")
		originalPersistentSecretData, err := cmd.CombinedOutput()
		Expect(err).ToNot(HaveOccurred())

		cmd = exec.Command("kubectl", "get", "secret", oemSecretName, "-o", "yaml")
		originalOemSecretData, err := cmd.CombinedOutput()
		Expect(err).ToNot(HaveOccurred())

		// Delete SealedVolume but keep secrets
		deleteSealedVolume(tpmHash)

		// Verify secrets still exist
		Expect(secretExists(persistentSecretName)).To(BeTrue())
		Expect(secretExists(oemSecretName)).To(BeTrue())

		// Recreate SealedVolume and verify secret reuse
		By("Recreating SealedVolume and verifying secret reuse for both partitions")
		createSealedVolumeWithAttestation(tpmHash, nil)

		// Should reuse existing secrets
		rebootAndConnect(testVM)
		verifyEncryptedPartition(testVM)

		// Verify the same secrets are being used
		cmd = exec.Command("kubectl", "get", "secret", persistentSecretName, "-o", "yaml")
		newPersistentSecretData, err := cmd.CombinedOutput()
		Expect(err).ToNot(HaveOccurred())

		cmd = exec.Command("kubectl", "get", "secret", oemSecretName, "-o", "yaml")
		newOemSecretData, err := cmd.CombinedOutput()
		Expect(err).ToNot(HaveOccurred())

		// The secret data should be identical (reused, not regenerated) for both partitions
		Expect(string(newPersistentSecretData)).To(Equal(string(originalPersistentSecretData)))
		Expect(string(newOemSecretData)).To(Equal(string(originalOemSecretData)))
	})
})
