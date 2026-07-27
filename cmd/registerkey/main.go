// Command registerkey registers an RSA public key with Buzz for OAuth 2.0.
//
//	go run ./cmd/registerkey -s SERVER_URL -u USER_ID -k KID -p PUBLIC_KEY_PATH [-t TOKEN]
//
// The admin Bearer token is read from -t, the BUZZ_ADMIN_TOKEN environment
// variable, or an interactive prompt (in that order).
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/AgilixLabs/BuzzApiSample-Go/internal/tool"
)

var kidRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func main() {
	server := flag.String("s", "", "Buzz API server URL (no trailing slash)")
	token := flag.String("t", "", "admin Bearer token (prefer BUZZ_ADMIN_TOKEN or the prompt)")
	userID := flag.String("u", "", "userid of the Application Identity account")
	kid := flag.String("k", "", "key id, e.g. 2025-q2")
	pub := flag.String("p", "", "path to the SPKI PEM public key")
	flag.Parse()

	if *server == "" || *userID == "" || *kid == "" || *pub == "" {
		fmt.Fprintln(os.Stderr, "Error: -s, -u, -k and -p are all required.")
		os.Exit(1)
	}
	srv := strings.TrimRight(*server, "/")
	if !kidRe.MatchString(*kid) {
		fmt.Fprintln(os.Stderr, "Error: invalid kid. Allowed: ASCII letters, digits, -, _, .  Max 128 chars.")
		os.Exit(1)
	}
	data, err := os.ReadFile(*pub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: public key file not found: %s\n", *pub)
		os.Exit(1)
	}
	if !strings.Contains(string(data), "BEGIN PUBLIC KEY") {
		fmt.Fprintln(os.Stderr, "Error: file is not a SubjectPublicKeyInfo PEM ('-----BEGIN PUBLIC KEY-----').")
		os.Exit(1)
	}

	tok := *token
	if tok == "" {
		tok = os.Getenv("BUZZ_ADMIN_TOKEN")
	}
	if tok == "" {
		tok = tool.PromptPassword("Admin Bearer token", "")
	}
	if tok == "" {
		fmt.Fprintln(os.Stderr, "Error: admin token is required.")
		os.Exit(1)
	}

	abs, _ := filepath.Abs(*pub)
	fmt.Println("Registering public key...")
	fmt.Printf("  URL  : %s/api/users/%s/keys/%s\n", srv, *userID, *kid)
	fmt.Printf("  Kid  : %s\n", *kid)
	fmt.Printf("  File : %s\n\n", abs)

	status, body := tool.RegisterPublicKey(srv, *userID, *kid, string(data), tok)
	os.Exit(report(status, body, *userID, *kid))
}

func report(status int, body, userID, kid string) int {
	switch status {
	case 204:
		fmt.Println("Public key registered successfully (HTTP 204).")
		fmt.Println()
		fmt.Println("Configure your application:")
		fmt.Printf("  oauthUserId = %s\n", userID)
		fmt.Printf("  oauthKid    = %s\n", kid)
		return 0
	case 400:
		fmt.Fprintln(os.Stderr, "Error: HTTP 400 Bad Request")
		fmt.Fprintln(os.Stderr, "  - Public key must be SPKI PEM and at least 2048 bits.")
		fmt.Fprintf(os.Stderr, "  - Account %s must have been created with type=applicationidentity.\n", userID)
	case 401, 403:
		fmt.Fprintf(os.Stderr, "Error: HTTP %d — admin token lacks Update User rights on account %s.\n", status, userID)
	case 404:
		fmt.Fprintln(os.Stderr, "Error: HTTP 404 — server URL or user id not found.")
	default:
		fmt.Fprintf(os.Stderr, "Error: unexpected HTTP %d\n", status)
	}
	if body != "" {
		fmt.Fprintf(os.Stderr, "Response: %s\n", body)
	}
	return 1
}
