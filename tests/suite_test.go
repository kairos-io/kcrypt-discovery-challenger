package e2e_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"strconv"
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
