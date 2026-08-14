// Command newkey generates an RSA key pair for Buzz OAuth 2.0 authentication.
//
//	go run ./cmd/newkey [-out DIR] [-bits N] [-force]
//
// Outputs private_key.pem (keep secret) and public_key.pem (register with Buzz).
// Uses only the Go standard library — no external OpenSSL needed.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/AgilixLabs/BuzzApiSample-Go/internal/tool"
)

func main() {
	out := flag.String("out", ".", "output directory for the key files")
	bits := flag.Int("bits", 2048, "RSA key size in bits (minimum 2048)")
	force := flag.Bool("force", false, "overwrite existing key files")
	flag.Parse()

	if !*force {
		if _, err := os.Stat(filepath.Join(*out, "private_key.pem")); err == nil {
			if !tool.Confirm("Key files already exist and will be overwritten.  Continue?", false) {
				fmt.Println("Aborted.")
				return
			}
			*force = true
		}
	}

	privPath, pubPath, err := tool.GenerateKeyPair(*out, *bits, *force)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nRSA key pair generated (%d bits):\n", *bits)
	fmt.Println("  Private key : " + privPath)
	fmt.Println("  Public key  : " + pubPath)
	fmt.Println("\nNext step: register the public key with Buzz.")
	fmt.Println("  go run ./cmd/registerkey -s https://backgroundapi.agilixbuzz.com -u <userid> -k <kid> -p public_key.pem")
	fmt.Println("\nIMPORTANT: Never commit private_key.pem to source control.")
}
