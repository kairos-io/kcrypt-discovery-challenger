package e2e_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/google/uuid"
	process "github.com/mudler/go-processmanager"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/spectrocloud/peg/matcher"
	machine "github.com/spectrocloud/peg/pkg/machine"
	"github.com/spectrocloud/peg/pkg/machine/types"
)

func TestE2e(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "kcrypt-challenger e2e test Suite")
}

type VMOptions struct {
	ISO        string
	User       string
	Password   string
	Memory     string
	CPUS       string
	RunSpicy   bool
	UseKVM     bool
	EmulateTPM bool
}

func DefaultVMOptions() VMOptions {
	var err error

	memory := os.Getenv("MEMORY")
	if memory == "" {
		memory = "2096"
	}
	cpus := os.Getenv("CPUS")
	if cpus == "" {
		cpus = "2"
	}

	runSpicy := false
	if s := os.Getenv("MACHINE_SPICY"); s != "" {
		runSpicy, err = strconv.ParseBool(os.Getenv("MACHINE_SPICY"))
		Expect(err).ToNot(HaveOccurred())
	}

	useKVM := false
	if envKVM := os.Getenv("KVM"); envKVM != "" {
		useKVM, err = strconv.ParseBool(os.Getenv("KVM"))
		Expect(err).ToNot(HaveOccurred())
	}

	return VMOptions{
		ISO:        os.Getenv("ISO"),
		User:       user(),
		Password:   pass(),
		Memory:     memory,
		CPUS:       cpus,
		RunSpicy:   runSpicy,
		UseKVM:     useKVM,
		EmulateTPM: true,
	}
}

func user() string {
	user := os.Getenv("SSH_USER")
	if user == "" {
		user = "kairos"
	}
	return user
}

func pass() string {
	pass := os.Getenv("SSH_PASS")
	if pass == "" {
		pass = "kairos"
	}

	return pass
}

func startVM(vmOpts VMOptions) (context.Context, VM) {
	if vmOpts.ISO == "" {
		fmt.Println("ISO missing")
		os.Exit(1)
	}

	vmName := uuid.New().String()

	stateDir, err := os.MkdirTemp("", "")
	Expect(err).ToNot(HaveOccurred())

	if vmOpts.EmulateTPM {
		emulateTPM(stateDir)
	}

	sshPort, err := getFreePort()
	Expect(err).ToNot(HaveOccurred())

	opts := []types.MachineOption{
		types.QEMUEngine,
		types.WithISO(vmOpts.ISO),
		types.WithMemory(vmOpts.Memory),
		types.WithCPU(vmOpts.CPUS),
		types.WithSSHPort(strconv.Itoa(sshPort)),
		types.WithID(vmName),
		types.WithSSHUser(vmOpts.User),
		types.WithSSHPass(vmOpts.Password),
		types.OnFailure(func(p *process.Process) {
			defer GinkgoRecover()

			var stdout, stderr, serial, status string

			if stdoutBytes, err := os.ReadFile(p.StdoutPath()); err != nil {
				stdout = fmt.Sprintf("Error reading stdout file: %s\n", err)
			} else {
				stdout = string(stdoutBytes)
			}

			if stderrBytes, err := os.ReadFile(p.StderrPath()); err != nil {
				stderr = fmt.Sprintf("Error reading stderr file: %s\n", err)
			} else {
				stderr = string(stderrBytes)
			}

			if status, err = p.ExitCode(); err != nil {
				status = fmt.Sprintf("Error reading exit code file: %s\n", err)
			}

			if serialBytes, err := os.ReadFile(path.Join(p.StateDir(), "serial.log")); err != nil {
				serial = fmt.Sprintf("Error reading serial log file: %s\n", err)
			} else {
				serial = string(serialBytes)
			}

			Fail(fmt.Sprintf("\nVM Aborted.\nstdout: %s\nstderr: %s\nserial: %s\nExit status: %s\n",
				stdout, stderr, serial, status))
		}),
		types.WithStateDir(stateDir),
		// Serial output to file: https://superuser.com/a/1412150
		func(m *types.MachineConfig) error {
			if vmOpts.EmulateTPM {
				m.Args = append(m.Args,
					"-chardev", fmt.Sprintf("socket,id=chrtpm,path=%s/swtpm-sock", path.Join(stateDir, "tpm")),
					"-tpmdev", "emulator,id=tpm0,chardev=chrtpm", "-device", "tpm-tis,tpmdev=tpm0")
			}
			m.Args = append(m.Args,
				"-chardev", fmt.Sprintf("stdio,mux=on,id=char0,logfile=%s,signal=off", path.Join(stateDir, "serial.log")),
				"-serial", "chardev:char0",
				"-mon", "chardev=char0",
			)
			return nil
		},
	}

	// Set this to true to debug.
	// You can connect to it with "spicy" or other tool.
	var spicePort int
	if vmOpts.RunSpicy {
		spicePort, err = getFreePort()
		Expect(err).ToNot(HaveOccurred())
		fmt.Printf("Spice port = %d\n", spicePort)
		opts = append(opts, types.WithDisplay(fmt.Sprintf("-spice port=%d,addr=127.0.0.1,disable-ticketing", spicePort)))
	}

	if vmOpts.UseKVM {
		opts = append(opts, func(m *types.MachineConfig) error {
			m.Args = append(m.Args,
				"-enable-kvm",
			)
			return nil
		})
	}

	m, err := machine.New(opts...)
	Expect(err).ToNot(HaveOccurred())

	vm := NewVM(m, stateDir)

	ctx, err := vm.Start(context.Background())
	Expect(err).ToNot(HaveOccurred())

	if vmOpts.RunSpicy {
		cmd := exec.Command("spicy",
			"-h", "127.0.0.1",
			"-p", strconv.Itoa(spicePort))
		err = cmd.Start()
		Expect(err).ToNot(HaveOccurred())
	}

	return ctx, vm
}

// return the PID of the swtpm (to be killed later) and the state directory
func emulateTPM(stateDir string) {
	t := path.Join(stateDir, "tpm")
	err := os.MkdirAll(t, os.ModePerm)
	Expect(err).ToNot(HaveOccurred())

	cmd := exec.Command("swtpm",
		"socket",
		"--tpmstate", fmt.Sprintf("dir=%s", t),
		"--ctrl", fmt.Sprintf("type=unixio,path=%s/swtpm-sock", t),
		"--tpm2", "--log", "level=20")
	err = cmd.Start()
	Expect(err).ToNot(HaveOccurred())

	err = os.WriteFile(path.Join(t, "pid"), []byte(strconv.Itoa(cmd.Process.Pid)), 0744)
	Expect(err).ToNot(HaveOccurred())
}

// https://gist.github.com/sevkin/96bdae9274465b2d09191384f86ef39d
// GetFreePort asks the kernel for a free open port that is ready to use.
func getFreePort() (port int, err error) {
	var a *net.TCPAddr
	if a, err = net.ResolveTCPAddr("tcp", "localhost:0"); err == nil {
		var l *net.TCPListener
		if l, err = net.ListenTCP("tcp", a); err == nil {
			defer l.Close()
			return l.Addr().(*net.TCPAddr).Port, nil
		}
	}
	return
}

// ========================================
// Common Test Helper Functions
// ========================================

// Helper to install Kairos with given config
func installKairosWithConfig(vm VM, config string) {
	configFile, err := os.CreateTemp("", "")
	Expect(err).ToNot(HaveOccurred())
	defer os.Remove(configFile.Name())

	err = os.WriteFile(configFile.Name(), []byte(config), 0744)
	Expect(err).ToNot(HaveOccurred())

	err = vm.Scp(configFile.Name(), "config.yaml", "0744")
	Expect(err).ToNot(HaveOccurred())

	By("Installing Kairos with config")
	installationOutput, err := vm.Sudo("/bin/bash -c 'set -o pipefail && kairos-agent manual-install --device auto config.yaml 2>&1 | tee manual-install.txt'")
	Expect(err).ToNot(HaveOccurred(), installationOutput)
}

// Helper to reboot and wait for connection
func rebootAndConnect(vm VM) {
	By("Rebooting VM")
	vm.Reboot()
	By("Waiting for VM to be connectable")
	vm.EventuallyConnects(1200)
}

// Helper to verify encrypted partition exists
func verifyEncryptedPartition(vm VM) {
	By("Verifying encrypted partition exists")
	out, err := vm.Sudo("blkid")
	Expect(err).ToNot(HaveOccurred(), out)
	Expect(out).To(MatchRegexp("TYPE=\"crypto_LUKS\" PARTLABEL=\"persistent\""), out)
	Expect(out).To(MatchRegexp("/dev/mapper.*LABEL=\"COS_PERSISTENT\""), out)
}

// Helper to get TPM hash from VM
func getTPMHash(vm VM) string {
	By("Getting TPM hash from VM")
	hash, err := vm.Sudo("/system/discovery/kcrypt-discovery-challenger")
	Expect(err).ToNot(HaveOccurred(), hash)
	return strings.TrimSpace(hash)
}

// Helper to test passphrase retrieval via CLI (returns true if successful, false if failed)
func checkPassphraseRetrieval(vm VM, partitionLabel string) bool {
	By(fmt.Sprintf("Testing passphrase retrieval for partition %s via CLI", partitionLabel))

	// Configure the CLI to use the challenger server
	cliCmd := fmt.Sprintf(`/system/discovery/kcrypt-discovery-challenger get \
	  --partition-label=%s \
	  --challenger-server="http://%s" \
	  2>/dev/null`, partitionLabel, os.Getenv("KMS_ADDRESS"))

	out, err := vm.Sudo(cliCmd)
	if err != nil {
		By(fmt.Sprintf("Passphrase retrieval failed: %v", err))
		return false
	}

	// Check if we got a passphrase (non-empty output)
	passphrase := strings.TrimSpace(out)
	success := len(passphrase) > 0

	if success {
		By("Passphrase retrieval successful")
	} else {
		By("Passphrase retrieval failed - empty response")
	}

	return success
}

// Helper to test passphrase retrieval with expectation (for cleaner test logic)
func expectPassphraseRetrieval(vm VM, partitionLabel string, shouldSucceed bool) {
	success := checkPassphraseRetrieval(vm, partitionLabel)
	if shouldSucceed {
		Expect(success).To(BeTrue(), "Passphrase retrieval should have succeeded")
	} else {
		Expect(success).To(BeFalse(), "Passphrase retrieval should have failed")
	}
}

// Helper to create SealedVolume with specific attestation configuration
func createSealedVolumeWithAttestation(tpmHash string, attestationConfig map[string]interface{}) {
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
  quarantined: false`, tpmHash, tpmHash)

	if attestationConfig != nil {
		sealedVolumeYaml += "\n  attestation:"
		for key, value := range attestationConfig {
			switch v := value.(type) {
			case string:
				sealedVolumeYaml += fmt.Sprintf("\n    %s: \"%s\"", key, v)
			case map[string]string:
				sealedVolumeYaml += fmt.Sprintf("\n    %s:", key)
				for k, val := range v {
					sealedVolumeYaml += "\n      pcrs:"
					sealedVolumeYaml += fmt.Sprintf("\n        \"%s\": \"%s\"", k, val)
				}
			}
		}
	}

	By(fmt.Sprintf("Creating SealedVolume with attestation config: %+v", attestationConfig))
	kubectlApplyYaml(sealedVolumeYaml)
}

// Helper to update SealedVolume attestation configuration
func updateSealedVolumeAttestation(tpmHashParam string, field, value string) {
	By(fmt.Sprintf("Updating SealedVolume %s field %s to %s", tpmHashParam, field, value))
	patch := fmt.Sprintf(`{"spec":{"attestation":{"%s":"%s"}}}`, field, value)
	cmd := exec.Command("kubectl", "patch", "sealedvolume", tpmHashParam, "--type=merge", "-p", patch)
	out, err := cmd.CombinedOutput()
	Expect(err).ToNot(HaveOccurred(), string(out))
}

// Helper to quarantine TPM
func quarantineTPM(tpmHash string) {
	By(fmt.Sprintf("Quarantining TPM %s", tpmHash))
	patch := `{"spec":{"quarantined":true}}`
	cmd := exec.Command("kubectl", "patch", "sealedvolume", tpmHash, "--type=merge", "-p", patch)
	out, err := cmd.CombinedOutput()
	Expect(err).ToNot(HaveOccurred(), string(out))
}

// Helper to unquarantine TPM
func unquarantineTPM(tpmHashParam string) {
	By(fmt.Sprintf("Unquarantining TPM %s", tpmHashParam))
	patch := `{"spec":{"quarantined":false}}`
	cmd := exec.Command("kubectl", "patch", "sealedvolume", tpmHashParam, "--type=merge", "-p", patch)
	out, err := cmd.CombinedOutput()
	Expect(err).ToNot(HaveOccurred(), string(out))
}

// Helper to delete SealedVolume
func deleteSealedVolume(tmpHashParam string) {
	By(fmt.Sprintf("Deleting SealedVolume %s", tmpHashParam))
	cmd := exec.Command("kubectl", "delete", "sealedvolume", tmpHashParam, "--ignore-not-found=true")
	out, err := cmd.CombinedOutput()
	Expect(err).ToNot(HaveOccurred(), string(out))
}

// Helper to delete SealedVolume from all namespaces
func deleteSealedVolumeAllNamespaces(tpmHashParam string) {
	By(fmt.Sprintf("Deleting SealedVolume %s from all namespaces", tpmHashParam))
	cmd := exec.Command("kubectl", "delete", "sealedvolume", tpmHashParam, "--ignore-not-found=true", "--all-namespaces")
	out, err := cmd.CombinedOutput()
	Expect(err).ToNot(HaveOccurred(), string(out))
}

// Helper to check if secret exists
func secretExists(secretName string) bool {
	cmd := exec.Command("kubectl", "get", "secret", secretName, "--ignore-not-found=true")
	out, err := cmd.CombinedOutput()
	return err == nil && len(out) > 0 && !strings.Contains(string(out), "NotFound")
}

// Helper to check if secret exists in namespace
func secretExistsInNamespace(secretName, namespace string) bool {
	cmd := exec.Command("kubectl", "get", "secret", secretName, "-n", namespace, "--ignore-not-found=true")
	out, err := cmd.CombinedOutput()
	return err == nil && len(out) > 0 && !strings.Contains(string(out), "NotFound")
}

// Helper to apply YAML to Kubernetes
func kubectlApplyYaml(yamlData string) {
	yamlFile, err := os.CreateTemp("", "")
	Expect(err).ToNot(HaveOccurred())
	defer os.Remove(yamlFile.Name())

	err = os.WriteFile(yamlFile.Name(), []byte(yamlData), 0744)
	Expect(err).ToNot(HaveOccurred())

	cmd := exec.Command("kubectl", "apply", "-f", yamlFile.Name())
	out, err := cmd.CombinedOutput()
	Expect(err).ToNot(HaveOccurred(), string(out))
}

// Helper to create SealedVolume with multi-partition configuration
func createMultiPartitionSealedVolume(tpmHash string, partitions []string) {
	sealedVolumeYaml := fmt.Sprintf(`---
apiVersion: keyserver.kairos.io/v1alpha1
kind: SealedVolume
metadata:
  name: "%s"
  namespace: default
spec:
  TPMHash: "%s"
  partitions:`, tpmHash, tpmHash)

	for _, partition := range partitions {
		sealedVolumeYaml += fmt.Sprintf(`
    - label: %s`, partition)
	}

	sealedVolumeYaml += "\n  quarantined: false"

	By(fmt.Sprintf("Creating multi-partition SealedVolume for partitions: %v", partitions))
	kubectlApplyYaml(sealedVolumeYaml)
}

// Helper to create SealedVolume in specific namespace
func createSealedVolumeInNamespace(tpmHash, namespace string) {
	// First create the namespace if it doesn't exist
	kubectlApplyYaml(fmt.Sprintf(`---
apiVersion: v1
kind: Namespace
metadata:
  name: %s`, namespace))

	sealedVolumeYaml := fmt.Sprintf(`---
apiVersion: keyserver.kairos.io/v1alpha1
kind: SealedVolume
metadata:
  name: "%s"
  namespace: %s
spec:
  TPMHash: "%s"
  partitions:
    - label: COS_PERSISTENT
  quarantined: false`, tpmHash, namespace, tpmHash)

	By(fmt.Sprintf("Creating SealedVolume in namespace %s", namespace))
	kubectlApplyYaml(sealedVolumeYaml)
}

// Helper to cleanup test resources
func cleanupTestResources(tpmHash string) {
	if tpmHash != "" {
		deleteSealedVolumeAllNamespaces(tpmHash)

		// Cleanup associated secrets in all namespaces
		cmd := exec.Command("kubectl", "delete", "secret", tpmHash, "--ignore-not-found=true", "--all-namespaces")
		cmd.CombinedOutput()

		cmd = exec.Command("kubectl", "delete", "secret", fmt.Sprintf("%s-cos-persistent", tpmHash), "--ignore-not-found=true", "--all-namespaces")
		cmd.CombinedOutput()

		// Cleanup test namespaces
		cmd = exec.Command("kubectl", "delete", "namespace", "test-ns-1", "--ignore-not-found=true")
		cmd.CombinedOutput()

		cmd = exec.Command("kubectl", "delete", "namespace", "test-ns-2", "--ignore-not-found=true")
		cmd.CombinedOutput()
	}
}

// Helper to install Kairos with config (handles both success and failure cases)
func installKairosWithConfigAdvanced(vm VM, config string, expectSuccess bool) {
	configFile, err := os.CreateTemp("", "")
	Expect(err).ToNot(HaveOccurred())
	defer os.Remove(configFile.Name())

	err = os.WriteFile(configFile.Name(), []byte(config), 0744)
	Expect(err).ToNot(HaveOccurred())

	err = vm.Scp(configFile.Name(), "config.yaml", "0744")
	Expect(err).ToNot(HaveOccurred())

	if expectSuccess {
		By("Installing Kairos with config")
		installationOutput, err := vm.Sudo("/bin/bash -c 'set -o pipefail && kairos-agent manual-install --device auto config.yaml 2>&1 | tee manual-install.txt'")
		Expect(err).ToNot(HaveOccurred(), installationOutput)
	} else {
		By("Installing Kairos with config (expecting failure)")
		vm.Sudo("/bin/bash -c 'set -o pipefail && kairos-agent manual-install --device auto config.yaml 2>&1 | tee manual-install.txt'")
	}
}

// Helper to cleanup VM and TPM emulator
func cleanupVM(vm VM) {
	By("Cleaning up test VM")
	err := vm.Destroy(func(vm VM) {
		// Stop TPM emulator
		tpmPID, err := os.ReadFile(path.Join(vm.StateDir, "tpm", "pid"))
		if err == nil && len(tpmPID) != 0 {
			pid, err := strconv.Atoi(string(tpmPID))
			if err == nil {
				syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})
	Expect(err).ToNot(HaveOccurred())
}
