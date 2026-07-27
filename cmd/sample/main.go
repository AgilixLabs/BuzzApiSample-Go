// Command sample runs the read-only Buzz API demo.
//
//	go run ./cmd/sample
package main

import (
	"fmt"
	"os"

	"github.com/AgilixLabs/BuzzApiSample-Go/internal/demo"
)

func main() {
	if err := demo.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
