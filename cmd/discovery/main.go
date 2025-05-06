package main

import (
	"fmt"
	"os"

	"github.com/kairos-io/kairos-challenger/cmd/discovery/client"
	"github.com/kairos-io/kairos-sdk/kcrypt/bus"
	"github.com/kairos-io/tpm-helpers"
	"github.com/mudler/go-pluggable"
)

func main() {
	if len(os.Args) >= 2 && isEventDefined(os.Args[1]) {
		c, err := client.NewClient()
		checkErr(err)
		checkErr(c.Start())
		return
	}

	pubhash, err := tpm.GetPubHash()
	checkErr(err)
	fmt.Print(pubhash)
}

func checkErr(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// isEventDefined checks whether an event is defined in the bus.
// It accepts strings or EventType, returns a boolean indicating that
// the event was defined among the events emitted by the bus.
func isEventDefined(i interface{}) bool {
	checkEvent := func(e pluggable.EventType) bool {
		if e == bus.EventDiscoveryPassword {
			return true
		}

		return false
	}

	switch f := i.(type) {
	case string:
		return checkEvent(pluggable.EventType(f))
	case pluggable.EventType:
		return checkEvent(f)
	default:
		return false
	}
}
