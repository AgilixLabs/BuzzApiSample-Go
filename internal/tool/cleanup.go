package tool

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Cleanup removes all artifacts created by Setup: the registered OAuth key and
// Application Identity account on the server, and the local key files and .env.
func Cleanup(yes bool) error {
	envFile := EnvPath()
	if _, err := os.Stat(envFile); err != nil {
		fmt.Println(".env not found — nothing to clean up.")
		return nil
	}
	LoadEnv(envFile)

	server := strings.TrimRight(os.Getenv(EnvServerURL), "/")
	oauthUserID := os.Getenv(EnvUserID)
	oauthKid := os.Getenv(EnvKid)
	privateKeyPath := os.Getenv(EnvKeyPath)

	if server == "" || oauthUserID == "" {
		return fmt.Errorf(".env is missing required fields (server url, oauth user id)")
	}

	fmt.Println("\n========================================================")
	fmt.Println("  Buzz API Sample - Cleanup")
	fmt.Println("========================================================")
	fmt.Println()
	fmt.Println("This will:")
	fmt.Printf("  * Delete OAuth public key (kid: %s) from Buzz\n", oauthKid)
	fmt.Printf("  * Delete Application Identity account (userid: %s) from Buzz\n", oauthUserID)
	if privateKeyPath != "" {
		fmt.Printf("  * Delete local key files near: %s\n", privateKeyPath)
	}
	fmt.Println("  * Delete .env")
	if !yes && !Confirm("\nThis action is irreversible.  Continue?", false) {
		fmt.Println("Aborted.")
		return nil
	}

	fmt.Println("\n-- Admin login -----------------------------------------")
	adminToken := AdminLogin(server)

	if oauthKid != "" {
		fmt.Printf("\n-- Deleting OAuth key (kid: %s) ----------------\n", oauthKid)
		status, _ := DeletePublicKey(server, oauthUserID, oauthKid, adminToken)
		switch {
		case status == 200 || status == 204:
			fmt.Printf("OAuth key deleted (HTTP %d).\n", status)
		case status == 404:
			fmt.Println("OAuth key not found (already deleted or never registered).")
		default:
			fmt.Fprintf(os.Stderr, "Warning: HTTP %d deleting key. Continuing.\n", status)
		}
	}

	fmt.Printf("\n-- Deleting Application Identity account (userid: %s) --\n", oauthUserID)
	resp := BuzzPost(server, "deleteusers",
		map[string]any{"requests": map[string]any{"user": []any{map[string]any{"userid": oauthUserID}}}}, adminToken)
	// The per-user outcome is authoritative.  The OUTER code is OK whenever the request
	// was merely well formed, so checking it first would report success for a delete
	// that was actually denied or whose target did not exist.
	delItem := Item(resp)
	delCode := delItem.Code
	if delCode == "" {
		delCode = ResponseCode(resp)
	}
	if delCode == "OK" {
		fmt.Println("Application Identity account deleted.")
	} else {
		detail := ""
		if delItem.Message != "" {
			detail = " - " + delItem.Message
		}
		fmt.Fprintf(os.Stderr, "Warning: delete returned code %q%s. Continuing.\n", delCode, detail)
	}

	fmt.Println("\n-- Removing local files --------------------------------")
	keyDir := "."
	if privateKeyPath != "" {
		keyDir = filepath.Dir(privateKeyPath)
	}
	removeFile(filepath.Join(keyDir, "private_key.pem"))
	removeFile(filepath.Join(keyDir, "public_key.pem"))
	if privateKeyPath != "" {
		removeFile(privateKeyPath)
	}
	removeFile(envFile)

	fmt.Println("\n========================================================")
	fmt.Println("  Cleanup complete.  Environment is back to a clean state.")
	fmt.Println("========================================================")
	fmt.Println()
	return nil
}

func removeFile(path string) {
	if path == "" {
		return
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return
	}
	if err := os.Remove(path); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not remove %s: %v\n", path, err)
	} else {
		abs, _ := filepath.Abs(path)
		fmt.Println("Removed: " + abs)
	}
}
