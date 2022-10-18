package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/jaypipes/ghw/pkg/block"
	"github.com/kairos-io/go-tpm"
	"github.com/kairos-io/kairos/pkg/machine"
	"github.com/kairos-io/kcrypt/pkg/bus"
	"gopkg.in/yaml.v3"

	"github.com/mudler/go-pluggable"
)

func main() {
	if len(os.Args) >= 2 && bus.IsEventDefined(os.Args[1]) {
		checkErr(start())
	}

	pubhash, _ := tpm.GetPubHash()
	fmt.Print(pubhash)
}

func checkErr(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	os.Exit(0)
}

func readServer() string {
	connectionDetails := config{}

	var server string
	// best-effort
	d, _ := machine.DotToYAML("/proc/cmdline")
	yaml.Unmarshal(d, &connectionDetails) //nolint:errcheck

	server = connectionDetails.Server
	if os.Getenv("WSS_SERVER") != "" {
		server = os.Getenv("WSS_SERVER")
	}

	return server
}

func waitPass(label string, attempts int) (pass string, err error) {
	for tries := 0; tries < attempts; tries++ {
		server := readServer()
		if server == "" {
			return "", fmt.Errorf("no server configured")
		}

		pass, err = getPass(server, label)
		if pass != "" || err == nil {
			return pass, err
		}
		time.Sleep(1 * time.Second)
	}
	return
}

func getPass(server, label string) (string, error) {
	msg, err := tpm.Get(server, tpm.WithAdditionalHeader("label", label))
	if err != nil {
		return "", err
	}
	result := map[string]interface{}{}
	err = json.Unmarshal(msg, &result)
	if err != nil {
		return "", err
	}
	p, ok := result["passphrase"]
	if ok {
		return fmt.Sprint(p), nil
	}
	return "", fmt.Errorf("pass for label not found")
}

type config struct {
	Server string `yaml:"challenger_server"`
}

// ❯ echo '{ "data": "{ \\"label\\": \\"LABEL\\" }"}' | sudo -E WSS_SERVER="http://localhost:8082/challenge" ./challenger "discovery.password"
func start() error {
	factory := pluggable.NewPluginFactory()

	// Input: bus.EventInstallPayload
	// Expected output: map[string]string{}
	factory.Add(bus.EventDiscoveryPassword, func(e *pluggable.Event) pluggable.EventResponse {

		b := &block.Partition{}
		err := json.Unmarshal([]byte(e.Data), b)
		if err != nil {
			return pluggable.EventResponse{
				Error: fmt.Sprintf("failed reading partitions: %s", err.Error()),
			}
		}

		// TODO: This should be 1 call, send both name and label to controller
		pass, err := waitPass(b.Label, 30)
		if err != nil {
			pass, err = waitPass(b.Name, 30)
			if err != nil {
				return pluggable.EventResponse{
					Error: fmt.Sprintf("failed getting pass: %s", err.Error()),
				}
			}
		}

		return pluggable.EventResponse{
			Data: pass,
		}
	})

	return factory.Run(pluggable.EventType(os.Args[1]), os.Stdin, os.Stdout)
}
