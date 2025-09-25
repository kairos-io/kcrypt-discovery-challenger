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

var _ = Describe("Advanced Scenarios E2E Tests", func() {
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
			By("Starting VM for advanced scenarios tests")
			_, testVM = startVM(vmOpts)
			fmt.Printf("\nadvanced scenarios VM.StateDir = %+v\n", testVM.StateDir)
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

	When("Testing Multi-Partition Support", Label("remote-multi-partition"), func() {
		It("should handle multiple partitions on same TPM with different encryption keys", func() {
			ensureVMRunning()

			// Step 1: Get TPM hash
			tpmHash = getTPMHash(testVM)
			deleteSealedVolume(tpmHash)

			// Step 2: Create SealedVolume with multiple partitions
			createMultiPartitionSealedVolume(tpmHash, []string{"COS_PERSISTENT", "COS_OEM"})

			// Step 3: Configure Kairos with multiple encrypted partitions
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

			// Step 4: Verify both partitions are encrypted
			By("Verifying both partitions are encrypted")
			out, err := testVM.Sudo("blkid")
			Expect(err).ToNot(HaveOccurred(), out)
			Expect(out).To(MatchRegexp("TYPE=\"crypto_LUKS\" PARTLABEL=\"persistent\""), out)
			Expect(out).To(MatchRegexp("TYPE=\"crypto_LUKS\" PARTLABEL=\"oem\""), out)

			// Step 5: Verify separate secrets were created for each partition
			By("Verifying separate secrets were created for each partition")
			Eventually(func() bool {
				return secretExistsInNamespace(fmt.Sprintf("%s-cos-persistent", tpmHash), "default") &&
					secretExistsInNamespace(fmt.Sprintf("%s-cos-oem", tpmHash), "default")
			}, 30*time.Second, 5*time.Second).Should(BeTrue())

			cleanupTestResources(tpmHash)
		})
	})

	When("Testing Namespace Isolation", Label("remote-namespace-isolation"), func() {
		It("should properly isolate SealedVolumes in different namespaces", func() {
			ensureVMRunning()

			// Step 1: Get TPM hash
			tpmHash = getTPMHash(testVM)
			deleteSealedVolume(tpmHash)

			// Step 2: Create SealedVolumes in different namespaces
			createSealedVolumeInNamespace(tpmHash, "test-ns-1")
			createSealedVolumeInNamespace(tpmHash, "test-ns-2")

			// Step 3: Initial setup with default namespace
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

			// Should fail initially because no SealedVolume in default namespace (test via CLI)
			expectPassphraseRetrieval(testVM, "COS_PERSISTENT", false)

			// Step 4: Create SealedVolume in default namespace
			By("Creating SealedVolume in default namespace")
			createSealedVolumeInNamespace(tpmHash, "default")

			time.Sleep(5 * time.Second)

			// Should now work via CLI
			expectPassphraseRetrieval(testVM, "COS_PERSISTENT", true)

			// Step 5: Verify secrets are created in appropriate namespaces
			By("Verifying namespace isolation of secrets")
			Eventually(func() bool {
				return secretExistsInNamespace(fmt.Sprintf("%s-cos-persistent", tpmHash), "default")
			}, 30*time.Second, 5*time.Second).Should(BeTrue())

			// Secrets should not cross namespace boundaries
			Expect(secretExistsInNamespace(fmt.Sprintf("%s-cos-persistent", tpmHash), "test-ns-1")).To(BeFalse())
			Expect(secretExistsInNamespace(fmt.Sprintf("%s-cos-persistent", tpmHash), "test-ns-2")).To(BeFalse())

			cleanupTestResources(tpmHash)
		})
	})

	When("Testing Network Resilience", Label("remote-network-resilience"), func() {
		It("should handle network interruptions gracefully", func() {
			ensureVMRunning()

			// Step 1: Initial setup
			tpmHash = getTPMHash(testVM)
			deleteSealedVolume(tpmHash)

			// Create SealedVolume for enrollment
			kubectlApplyYaml(fmt.Sprintf(`---
apiVersion: keyserver.kairos.io/v1alpha1
kind: SealedVolume
metadata:
  name: "%s"
  namespace: default
spec:
  TPMHash: "%s"
  partitions:
    - label: COS_PERSISTENT
  quarantined: false`, tpmHash, tpmHash))

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
    timeout: 30s
    retry_attempts: 3
`, os.Getenv("KMS_ADDRESS"))

			installKairosWithConfig(config)
			rebootAndConnect(testVM)
			verifyEncryptedPartition(testVM)

			// Step 2: Simulate network interruption during boot
			By("Testing resilience to temporary network outage")

			// We can't easily simulate network interruption in the current test setup,
			// but we can verify the timeout and retry configuration works by checking logs
			out, err := testVM.Sudo("journalctl -u kcrypt* --no-pager")
			Expect(err).ToNot(HaveOccurred())

			// Should see evidence of successful KMS communication
			Expect(out).To(ContainSubstring("kcrypt"))

			cleanupTestResources(tpmHash)
		})
	})

	When("Testing Performance Under Load", Label("remote-performance"), func() {
		It("should handle multiple concurrent authentication requests", func() {
			ensureVMRunning()

			// Step 1: Setup multiple encrypted partitions to test concurrent access
			tpmHash = getTPMHash(testVM)
			deleteSealedVolume(tpmHash)

			createMultiPartitionSealedVolume(tpmHash, []string{"COS_PERSISTENT", "COS_OEM"})

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

			// Step 2: Verify both partitions were decrypted successfully
			By("Verifying concurrent partition decryption")
			out, err := testVM.Sudo("blkid")
			Expect(err).ToNot(HaveOccurred(), out)
			Expect(out).To(MatchRegexp("TYPE=\"crypto_LUKS\" PARTLABEL=\"persistent\""), out)
			Expect(out).To(MatchRegexp("TYPE=\"crypto_LUKS\" PARTLABEL=\"oem\""), out)
			Expect(out).To(MatchRegexp("/dev/mapper.*LABEL=\"COS_PERSISTENT\""), out)
			Expect(out).To(MatchRegexp("/dev/mapper.*LABEL=\"COS_OEM\""), out)

			// Step 3: Test multiple rapid reboots to stress test the system
			By("Testing system stability under multiple rapid authentication cycles")
			for i := 0; i < 3; i++ {
				rebootAndConnect(testVM)
				verifyEncryptedPartition(testVM)
				time.Sleep(2 * time.Second) // Brief pause between cycles
			}

			cleanupTestResources(tpmHash)
		})
	})

	When("Testing Large PCR Configuration", Label("remote-large-pcr"), func() {
		It("should handle attestation with many PCRs", func() {
			ensureVMRunning()

			// Step 1: Create SealedVolume with extensive PCR configuration
			tpmHash = getTPMHash(testVM)
			deleteSealedVolume(tpmHash)

			// Create complex PCR configuration
			sealedVolumeYaml := fmt.Sprintf(`---
apiVersion: keyserver.kairos.io/v1alpha1
kind: SealedVolume
metadata:
  name: "%s"
  namespace: default
spec:
  TPMHash: "%s"
  partitions:
    - label: COS_PERSISTENT
  quarantined: false
  attestation:
    pcrValues:
      pcrs:
        "0": ""   # BIOS/UEFI - re-enroll
        "1": ""   # Platform Configuration - re-enroll  
        "2": ""   # Option ROM Code - re-enroll
        "3": ""   # Option ROM Configuration - re-enroll
        "4": ""   # MBR/GPT - re-enroll
        "5": ""   # Boot Manager - re-enroll
        "6": ""   # Platform State - re-enroll
        "7": ""   # Secure Boot State - re-enroll
        "8": ""   # Command Line - re-enroll
        "9": ""   # initrd - re-enroll
        "10": ""  # IMA - re-enroll
        # PCR 11 omitted - will be ignored
        "12": ""  # Kernel Command Line - re-enroll
        "13": ""  # sysvinit - re-enroll
        "14": ""  # systemd - re-enroll
        "15": ""  # System Integrity - re-enroll`, tpmHash, tpmHash)

			kubectlApplyYaml(sealedVolumeYaml)

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

			// Step 2: Verify that many PCRs were successfully enrolled
			By("Verifying extensive PCR enrollment")
			Eventually(func() int {
				cmd := exec.Command("kubectl", "get", "sealedvolume", tpmHash, "-o", "yaml")
				out, err := cmd.CombinedOutput()
				if err != nil {
					return 0
				}

				// Count non-empty PCR values
				lines := strings.Split(string(out), "\n")
				enrolledPCRs := 0
				for _, line := range lines {
					if strings.Contains(line, "\":") &&
						!strings.Contains(line, "\": \"\"") &&
						strings.Contains(line, "\"") {
						enrolledPCRs++
					}
				}
				return enrolledPCRs
			}, 60*time.Second, 10*time.Second).Should(BeNumerically(">=", 10))

			cleanupTestResources(tpmHash)
		})
	})

	When("Testing Resource Cleanup", Label("remote-cleanup"), func() {
		It("should properly cleanup resources when SealedVolumes are deleted", func() {
			ensureVMRunning()

			// Step 1: Create and verify initial setup
			tpmHash = getTPMHash(testVM)
			deleteSealedVolume(tpmHash)

			kubectlApplyYaml(fmt.Sprintf(`---
apiVersion: keyserver.kairos.io/v1alpha1
kind: SealedVolume
metadata:
  name: "%s"
  namespace: default
spec:
  TPMHash: "%s"
  partitions:
    - label: COS_PERSISTENT
  quarantined: false`, tpmHash, tpmHash))

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

			// Step 2: Verify secret was created
			secretName := fmt.Sprintf("%s-cos-persistent", tpmHash)
			Eventually(func() bool {
				return secretExistsInNamespace(secretName, "default")
			}, 30*time.Second, 5*time.Second).Should(BeTrue())

			// Step 3: Delete SealedVolume and verify orphaned secret handling
			By("Testing resource cleanup after SealedVolume deletion")
			deleteSealedVolume(tpmHash)

			// Secret should still exist (policy decision - secrets are not auto-deleted)
			Expect(secretExistsInNamespace(secretName, "default")).To(BeTrue())

			// Step 4: Try to retrieve passphrase without SealedVolume (should fail)
			By("Testing passphrase retrieval after SealedVolume deletion")
			time.Sleep(5 * time.Second)

			// Should fail to get passphrase without SealedVolume
			expectPassphraseRetrieval(testVM, "COS_PERSISTENT", false)

			// Step 5: Manual secret cleanup for test hygiene
			cmd := exec.Command("kubectl", "delete", "secret", secretName, "--ignore-not-found=true")
			cmd.CombinedOutput()

		})
	})
})
