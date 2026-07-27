// Command setup runs the interactive one-time Buzz OAuth 2.0 setup.
//
//	go run ./cmd/setup
//
// Every prompt falls back to a BUZZ_* environment variable, so it can also run
// unattended (see internal/tool).
package main

import (
	"fmt"
	"os"

	"github.com/AgilixLabs/BuzzApiSample-Go/internal/tool"
)

func main() {
	if err := tool.Setup(); err != nil {
		fmt.Fprintf(os.Stderr, "\nError: %v\n", err)
		os.Exit(1)
	}
}
