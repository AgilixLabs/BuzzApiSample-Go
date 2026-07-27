// Command cleanup removes all artifacts created by setup.
//
//	go run ./cmd/cleanup [--yes]
//
// Deletes the registered OAuth key and Application Identity account on the
// server, and the local key files and .env. Pass --yes to skip confirmation.
package main

import (
	"fmt"
	"os"

	"github.com/AgilixLabs/BuzzApiSample-Go/internal/tool"
)

func main() {
	yes := false
	for _, a := range os.Args[1:] {
		if a == "--yes" || a == "-yes" || a == "-y" {
			yes = true
		}
	}
	if err := tool.Cleanup(yes); err != nil {
		fmt.Fprintf(os.Stderr, "\nError: %v\n", err)
		os.Exit(1)
	}
}
