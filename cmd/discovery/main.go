package main

import (
	"fmt"
	"os"

	"github.com/kairos-io/kairos-challenger/cmd/discovery/client"
	"github.com/kairos-io/kcrypt/pkg/bus"
	"github.com/kairos-io/tpm-helpers"
)

func main() {
	if len(os.Args) >= 2 && bus.IsEventDefined(os.Args[1]) {
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
