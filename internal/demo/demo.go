// Package demo contains the read-only Buzz API sample.
package demo

import (
	"fmt"
	"strings"

	"github.com/AgilixLabs/BuzzApiSample-Go/buzzapi"
	"github.com/AgilixLabs/BuzzApiSample-Go/internal/tool"
)

// Run loads configuration, builds a client, and runs the read-only demo:
//
//	getuser2  -> verify authentication and discover the home domain
//	getdomain2 -> read domain details
//
// It is intentionally read-only and can be run repeatedly without modifying data.
func Run() error {
	cfg, err := tool.ReadConfig()
	if err != nil {
		return fmt.Errorf("%w\n  Run setup:  go run ./cmd/run", err)
	}

	userAgent := fmt.Sprintf("BuzzApiClient/1.0.0 (Go; %s; %s)", cfg.ApplicationInformation, cfg.ContactInformation)

	// Show info/warn/error; suppress debug tracing for a clean demo.
	logger := func(level, message string) {
		if level == "debug" {
			return
		}
		fmt.Printf("%s: %s\n", strings.ToUpper(level), message)
	}

	client, err := buzzapi.FromPEMFile(cfg.ServerURL, userAgent, cfg.OAuthUserID, cfg.OAuthKid, cfg.PrivateKeyPath,
		&buzzapi.Options{Logger: logger})
	if err != nil {
		return err
	}
	return runSample(client, logger)
}

func runSample(client *buzzapi.Client, log buzzapi.Logger) error {
	fmt.Println()
	fmt.Println("========================================================")
	fmt.Println("  Buzz API OAuth 2.0 Sample - Read-Only Demo (Go)")
	fmt.Println("========================================================")
	fmt.Println()

	// getuser2: verify authentication and discover the home domain.
	fmt.Println("-- getuser2 (verify authentication) --------------------")
	userResp, err := client.JSONRequest("GET", "getuser2", nil, nil, true)
	if err != nil {
		return err
	}
	userNode, err := client.VerifyResponse(userResp, true)
	if err != nil {
		return err
	}
	user := asMap(userNode["user"])

	// The User schema names this "id".  ("userid" is the CreateUsers2 *response* field
	// for a newly created user - a different command, not an alias here.)
	userID := str(user["id"])
	domainID := str(user["domainid"])
	log("info", fmt.Sprintf("Authenticated as user %s (%q, userid: %s)",
		str(user["username"]), str(user["firstname"])+" "+str(user["lastname"]), userID))
	log("info", "Home domain: "+domainID)

	// getdomain2: read details about the account's home domain.
	if domainID != "" {
		fmt.Println()
		fmt.Println("-- getdomain2 (read domain details) --------------------")
		domainResp, err := client.JSONRequest("GET", "getdomain2", map[string]string{"domainid": domainID}, nil, true)
		if err != nil {
			return err
		}
		domainNode, err := client.VerifyResponse(domainResp, true)
		if err != nil {
			return err
		}
		domain := asMap(domainNode["domain"])
		log("info", "Domain name: "+str(domain["name"]))
		log("info", "Userspace  : "+str(domain["userspace"]))
		if t := str(domain["type"]); t != "" {
			log("info", "Type       : "+t)
		}
	}

	fmt.Println()
	fmt.Println("========================================================")
	fmt.Println("  All API calls succeeded.  OAuth integration is working.")
	fmt.Println("  No data was created or modified.")
	fmt.Println("========================================================")
	fmt.Println()
	return nil
}

func asMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func str(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		// Buzz ids come back as JSON numbers or strings; render integers cleanly.
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%v", t)
	default:
		return fmt.Sprintf("%v", v)
	}
}
