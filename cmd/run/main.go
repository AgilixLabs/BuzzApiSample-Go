// Command run is the entry point for the Buzz API sample.
//
//	go run ./cmd/run [--setup]
//
// If setup has not been completed (.env missing or the private key file not
// readable), the interactive setup runs first. Then the read-only sample runs.
// Pass --setup to force re-running setup.
//
// The sample runs under a temporary application name (quickStartName), so the quick
// start works before you have named your application in internal/demo/demo.go. The
// name is supplied to that one build through a go build overlay and is never written
// into the source; set your own name in demo.go before using the code anywhere else.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/AgilixLabs/BuzzApiSample-Go/internal/tool"
)

// quickStartName is the User-Agent application name the quick start runs the sample under.
const quickStartName = "QuickStartSample/1.0"

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
	os.Exit(runSample())
}

// runSample runs ./cmd/sample with YOUR_APPLICATION_NAME defined by a go build overlay: a
// file that exists only in a temporary directory and only for this build, so
// internal/demo/demo.go is never edited. Returns the exit code.
func runSample() int {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	dir, err := os.MkdirTemp("", "sample-quickstart-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(dir)

	nameFile := filepath.Join(dir, "name.go")
	src := fmt.Sprintf("package demo\n\nconst YOUR_APPLICATION_NAME = %q\n", quickStartName)
	overlay, err := json.Marshal(map[string]map[string]string{
		"Replace": {filepath.Join(wd, "internal", "demo", "zz_quickstart_name.go"): nameFile},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	overlayFile := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(nameFile, []byte(src), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.WriteFile(overlayFile, overlay, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	cmd := exec.Command("go", "run", "-overlay", overlayFile, "./cmd/sample")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "Could not run the sample with go run: %v\n", err)
		return 1
	}
	return 0
}
