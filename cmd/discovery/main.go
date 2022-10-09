package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/jaypipes/ghw/pkg/block"
	"github.com/kairos-io/go-tpm"
	"github.com/kairos-io/kcrypt/pkg/bus"

	"github.com/mudler/go-pluggable"
)

func main() {
	if len(os.Args) >= 2 && bus.IsEventDefined(os.Args[1]) {
		checkErr(start())
	}
}

func checkErr(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	os.Exit(0)
}

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

		msg, err := tpm.Get(os.Getenv("WSS_SERVER"), tpm.WithAdditionalHeader("label", b.Label))
		if err != nil {
			return pluggable.EventResponse{
				Error: fmt.Sprintf("failed contacting from wss server: %s", err.Error()),
			}
		}
		result := map[string]interface{}{}
		err = json.Unmarshal(msg, &result)
		if err != nil {
			return pluggable.EventResponse{
				Error: fmt.Sprintf("failed reading from wss server: %s", err.Error()),
			}
		}
		p, ok := result["passphrase"]
		if !ok {
			return pluggable.EventResponse{
				Error: "not found",
			}
		}

		return pluggable.EventResponse{
			Data: fmt.Sprint(p),
		}
	})

	return factory.Run(pluggable.EventType(os.Args[1]), os.Stdin, os.Stdout)
}
