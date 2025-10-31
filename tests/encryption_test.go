package e2e_test

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"syscall"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/spectrocloud/peg/matcher"
	"gopkg.in/yaml.v3"

	client "github.com/kairos-io/kairos-challenger/cmd/discovery/client"
)

var installationOutput string
var vm VM
var mdnsVM VM

var _ = Describe("kcrypt encryption", Label("encryption-tests"), func() {
	var config string
	var vmOpts VMOptions
	var expectedInstallationSuccess bool

	BeforeEach(func() {
		expectedInstallationSuccess = true

		vmOpts = DefaultVMOptions()
		RegisterFailHandler(printInstallationOutput)
		_, vm = startVM(vmOpts)
		fmt.Printf("\nvm.StateDir = %+v\n", vm.StateDir)

		vm.EventuallyConnects(1200)
	})

	JustBeforeEach(func() {
		configFile, err := os.CreateTemp("", "")
		Expect(err).ToNot(HaveOccurred())
		defer os.Remove(configFile.Name())

		err = os.WriteFile(configFile.Name(), []byte(config), 0744)
		Expect(err).ToNot(HaveOccurred())

		err = vm.Scp(configFile.Name(), "config.yaml", "0744")
		Expect(err).ToNot(HaveOccurred())

		installationOutput, err = vm.Sudo("/bin/bash -c 'set -o pipefail && kairos-agent manual-install --device auto config.yaml 2>&1 | tee manual-install.txt'")
		if expectedInstallationSuccess {
			Expect(err).ToNot(HaveOccurred(), installationOutput)
		}
	})

	AfterEach(func() {
		vm.GatherLog("/run/immucore/immucore.log")
		err := vm.Destroy(func(vm VM) {
			// Stop TPM emulator
			tpmPID, err := os.ReadFile(path.Join(vm.StateDir, "tpm", "pid"))
			Expect(err).ToNot(HaveOccurred())

			if len(tpmPID) != 0 {
				pid, err := strconv.Atoi(string(tpmPID))
				Expect(err).ToNot(HaveOccurred())

				syscall.Kill(pid, syscall.SIGKILL)
			}
		})
		Expect(err).ToNot(HaveOccurred())
	})

	When("discovering KMS with mdns", Label("discoverable-kms"), func() {
		var tpmHash string
		var mdnsHostname string

		BeforeEach(func() {
			By("creating the secret in kubernetes")
			tpmHash = createTPMPassphraseSecret(vm)

			mdnsHostname = "discoverable-kms.local"

			By("deploying simple-mdns-server vm")
			mdnsVM = deploySimpleMDNSServer(mdnsHostname)

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
  reboot: false # we will reboot manually

kcrypt:
  challenger:
    mdns: true
    challenger_server: "http://%[1]s"
`, mdnsHostname)
		})

		AfterEach(func() {
			sealedVolumeName := getSealedVolumeName(tpmHash)
			cmd := exec.Command("kubectl", "delete", "sealedvolume", sealedVolumeName)
			out, err := cmd.CombinedOutput()
			Expect(err).ToNot(HaveOccurred(), out)

			err = mdnsVM.Destroy(func(vm VM) {})
			Expect(err).ToNot(HaveOccurred())
		})

		It("discovers the KMS using mdns", func() {
			Skip("TODO: make this test work")

			By("rebooting")
			vm.Reboot()
			By("checking that we can connect after installation")
			vm.EventuallyConnects(1200)
			By("checking if we got an encrypted partition")
			out, err := vm.Sudo("blkid")
			Expect(err).ToNot(HaveOccurred(), out)
			Expect(out).To(MatchRegexp("TYPE=\"crypto_LUKS\" PARTLABEL=\"persistent\""), out)
		})
	})

	// https://kairos.io/docs/advanced/partition_encryption/#offline-mode
	When("doing local encryption", Label("local-encryption"), func() {
		BeforeEach(func() {
			config = `#cloud-config

install:
  encrypted_partitions:
  - COS_PERSISTENT
  reboot: false # we will reboot manually

hostname: metal-{{ trunc 4 .MachineID }}
users:
- name: kairos
  passwd: kairos
`
		})

		It("boots and has an encrypted partition", func() {
			vm.Reboot()
			vm.EventuallyConnects(1200)
			out, err := vm.Sudo("blkid")
			Expect(err).ToNot(HaveOccurred(), out)
			Expect(out).To(MatchRegexp("TYPE=\"crypto_LUKS\" PARTLABEL=\"persistent\""), out)
		})
	})

	//https://kairos.io/docs/advanced/partition_encryption/#online-mode
	When("using a remote key management server (automated passphrase generation)", Label("remote-auto"), func() {
		var tpmHash string

		BeforeEach(func() {
			tpmHash = createTPMPassphraseSecret(vm)
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
  reboot: false # we will reboot manually

kcrypt:
  challenger:
    challenger_server: "http://%s"
    nv_index: ""
    c_index: ""
    tpm_device: ""
`, os.Getenv("KMS_ADDRESS"))
		})

		AfterEach(func() {
			sealedVolumeName := getSealedVolumeName(tpmHash)
			cmd := exec.Command("kubectl", "delete", "sealedvolume", sealedVolumeName)
			out, err := cmd.CombinedOutput()
			Expect(err).ToNot(HaveOccurred(), out)
		})

		It("creates a passphrase and a key/pair to decrypt it", func() {
			// Expect a LUKS partition
			vm.Reboot(750)
			vm.EventuallyConnects(1200)
			out, err := vm.Sudo("blkid")
			Expect(err).ToNot(HaveOccurred(), out)
			Expect(out).To(MatchRegexp("TYPE=\"crypto_LUKS\" PARTLABEL=\"persistent\""), out)

			// Expect a secret to be created
			cmd := exec.Command("kubectl", "get", "secrets",
				fmt.Sprintf("%s-cos-persistent", getSealedVolumeName(tpmHash)),
				"-o=go-template='{{.data.generated_by|base64decode}}'",
			)

			secretOut, err := cmd.CombinedOutput()
			Expect(err).ToNot(HaveOccurred(), string(secretOut))
			Expect(string(secretOut)).To(MatchRegexp("tpm"))
		})
	})

	// https://kairos.io/docs/advanced/partition_encryption/#scenario-static-keys
	When("using a remote key management server (static keys)", Label("remote-static"), func() {
		var tpmHash string
		var sealedVolumeName string
		var secretName string
		var err error

		BeforeEach(func() {
			tpmHash, err = vm.Sudo("/system/discovery/kcrypt-discovery-challenger")
			Expect(err).ToNot(HaveOccurred(), tpmHash)
			tpmHash = strings.TrimSpace(tpmHash)

			// Use safe Kubernetes names (TPM hash is 64 chars, exceeds 63 char limit)
			sealedVolumeName = getSealedVolumeName(tpmHash)
			secretName = fmt.Sprintf("%s-cos-persistent", sealedVolumeName)

			kubectlApplyYaml(fmt.Sprintf(`---
apiVersion: v1
kind: Secret
metadata:
  name: %[1]s
  namespace: default
type: Opaque
stringData:
  passphrase: "awesome-plaintext-passphrase"
`, secretName))

			kubectlApplyYaml(fmt.Sprintf(`---
apiVersion: keyserver.kairos.io/v1alpha1
kind: SealedVolume
metadata:
    name: %[1]s
    namespace: default
spec:
  TPMHash: "%[2]s"
  partitions:
    - label: COS_PERSISTENT
      secret:
       name: %[3]s
       path: passphrase
  quarantined: false
`, sealedVolumeName, tpmHash, secretName))

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
  reboot: false # we will reboot manually

kcrypt:
  challenger:
    challenger_server: "http://%s"
`, os.Getenv("KMS_ADDRESS"))
		})

		AfterEach(func() {
			cmd := exec.Command("kubectl", "delete", "sealedvolume", sealedVolumeName)
			out, err := cmd.CombinedOutput()
			Expect(err).ToNot(HaveOccurred(), out)

			cmd = exec.Command("kubectl", "delete", "secret", secretName)
			out, err = cmd.CombinedOutput()
			Expect(err).ToNot(HaveOccurred(), out)
		})

		It("creates uses the existing passphrase to decrypt it", func() {
			// Expect a LUKS partition
			vm.Reboot()
			vm.EventuallyConnects(1200)
			out, err := vm.Sudo("blkid")
			Expect(err).ToNot(HaveOccurred(), out)
			Expect(out).To(MatchRegexp("TYPE=\"crypto_LUKS\" PARTLABEL=\"persistent\""), out)
			Expect(out).To(MatchRegexp("/dev/mapper.*LABEL=\"COS_PERSISTENT\""), out)
		})
	})

	When("the certificate is pinned on the configuration", Label("remote-https-pinned"), func() {
		var tpmHash string

		BeforeEach(func() {
			tpmHash = createTPMPassphraseSecret(vm)
			cert := getChallengerServerCert()
			kcryptConfig := createConfigWithCert(fmt.Sprintf("https://%s", os.Getenv("KMS_ADDRESS")), cert)
			kcryptConfigBytes, err := yaml.Marshal(kcryptConfig)
			Expect(err).ToNot(HaveOccurred())
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
  reboot: false # we will reboot manually

%s

`, string(kcryptConfigBytes))
		})

		It("successfully talks to the server", func() {
			vm.Reboot()
			vm.EventuallyConnects(1200)
			out, err := vm.Sudo("blkid")
			Expect(err).ToNot(HaveOccurred(), out)
			Expect(out).To(MatchRegexp("TYPE=\"crypto_LUKS\" PARTLABEL=\"persistent\""), out)
			Expect(out).To(MatchRegexp("/dev/mapper.*LABEL=\"COS_PERSISTENT\""), out)
		})

		AfterEach(func() {
			sealedVolumeName := getSealedVolumeName(tpmHash)
			cmd := exec.Command("kubectl", "delete", "sealedvolume", sealedVolumeName)
			out, err := cmd.CombinedOutput()
			Expect(err).ToNot(HaveOccurred(), out)
		})
	})

	When("the no certificate is set in the configuration", Label("remote-https-bad-cert"), func() {
		var tpmHash string

		BeforeEach(func() {
			tpmHash = createTPMPassphraseSecret(vm)
			expectedInstallationSuccess = false

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
  reboot: false # we will reboot manually

kcrypt:
  challenger:
    challenger_server: "https://%s"
`, os.Getenv("KMS_ADDRESS"))
		})

		It("fails to talk to the server", func() {
			out, err := vm.Sudo("cat manual-install.txt")
			Expect(err).ToNot(HaveOccurred(), out)
			Expect(out).To(MatchRegexp("failed to verify certificate: x509: certificate signed by unknown authority"))
		})

		AfterEach(func() {
			sealedVolumeName := getSealedVolumeName(tpmHash)
			cmd := exec.Command("kubectl", "delete", "sealedvolume", sealedVolumeName)
			out, err := cmd.CombinedOutput()
			Expect(err).ToNot(HaveOccurred(), out)
		})
	})
})

func printInstallationOutput(message string, callerSkip ...int) {
	fmt.Printf("This is the installation output in case it's useful:\n%s\n", installationOutput)

	// Ensures the correct line numbers are reported
	Fail(message, callerSkip[0]+1)
}

func getChallengerServerCert() string {
	cmd := exec.Command(
		"kubectl", "get", "secret", "-n", "default", "kms-tls",
		"-o", `go-template={{ index .data "ca.crt" | base64decode }}`)
	out, err := cmd.CombinedOutput()
	Expect(err).ToNot(HaveOccurred(), string(out))

	return string(out)
}

func createConfigWithCert(server, cert string) client.Config {
	c := client.Config{}
	c.Kcrypt.Challenger.Server = server
	c.Kcrypt.Challenger.Certificate = cert

	return c
}

func createTPMPassphraseSecret(vm VM) string {
	tpmHash, err := vm.Sudo("/system/discovery/kcrypt-discovery-challenger")
	Expect(err).ToNot(HaveOccurred(), tpmHash)
	tpmHash = strings.TrimSpace(tpmHash)

	// Use safe Kubernetes name (TPM hash is 64 chars, exceeds 63 char limit)
	sealedVolumeName := getSealedVolumeName(tpmHash)

	kubectlApplyYaml(fmt.Sprintf(`---
apiVersion: keyserver.kairos.io/v1alpha1
kind: SealedVolume
metadata:
  name: "%[1]s"
  namespace: default
spec:
  TPMHash: "%[2]s"
  partitions:
    - label: COS_PERSISTENT
  quarantined: false
`, sealedVolumeName, tpmHash))

	return tpmHash
}

// We run the simple-mdns-server (https://github.com/kairos-io/simple-mdns-server/)
// inside a VM next to the one we test. The server advertises the KMS as running on 10.0.2.2
// (the host machine). This is a "hack" and is needed because of how the default
// networking in qemu works. We need to be within the same network and that
// network is only available withing another VM.
// https://wiki.qemu.org/Documentation/Networking
func deploySimpleMDNSServer(hostname string) VM {
	opts := DefaultVMOptions()
	opts.Memory = "2000"
	opts.CPUS = "1"
	opts.EmulateTPM = false
	_, vm := startVM(opts)
	vm.EventuallyConnects(1200)

	out, err := vm.Sudo(`curl -s https://api.github.com/repos/kairos-io/simple-mdns-server/releases/latest | jq -r .assets[].browser_download_url | grep $(uname -m) | xargs curl -L -o sms.tar.gz`)
	Expect(err).ToNot(HaveOccurred(), string(out))

	out, err = vm.Sudo("tar xvf sms.tar.gz")
	Expect(err).ToNot(HaveOccurred(), string(out))

	// Start the simple-mdns-server in the background
	out, err = vm.Sudo(fmt.Sprintf(
		"/bin/bash -c './simple-mdns-server --port 80 --address 10.0.2.2 --serviceType _kcrypt._tcp --hostName %s &'", hostname))
	Expect(err).ToNot(HaveOccurred(), string(out))

	return vm
}
