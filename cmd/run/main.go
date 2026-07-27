// Command run is the entry point for the Buzz API sample.
//
//	go run ./cmd/run [--setup]
//
// If setup has not been completed (.env missing or the private key file not
// readable), the interactive setup runs first. Then the read-only sample runs.
// Pass --setup to force re-running setup.
package main

import (
	"fmt"
	"os"

	"github.com/AgilixLabs/BuzzApiSample-Go/internal/demo"
	"github.com/AgilixLabs/BuzzApiSample-Go/internal/tool"
)

func main() {
	force := false
	for _, a := range os.Args[1:] {
		if a == "--setup" || a == "-setup" {
			force = true
		}
	}

	if force || !tool.SetupComplete() {
		if force {
			fmt.Println("\n-- Running setup ---------------------------------------")
		} else {
			fmt.Println("\n-- Setup not complete - starting interactive setup -----")
		}
		if err := tool.Setup(); err != nil {
			fmt.Fprintf(os.Stderr, "\nSetup did not complete: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Println("\n-- Running the sample ----------------------------------")
	if err := demo.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
