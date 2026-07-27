package tool

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var kidRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// SetupComplete reports whether one-time setup has been done: required config is
// present and the private key file is readable.
func SetupComplete() bool {
	LoadEnv(EnvPath())
	for _, e := range []string{EnvServerURL, EnvUserID, EnvKid, EnvKeyPath} {
		if os.Getenv(e) == "" {
			return false
		}
	}
	keyPath := os.Getenv(EnvKeyPath)
	if keyPath == "" {
		return false
	}
	_, err := os.Stat(keyPath)
	return err == nil
}

// Setup runs the interactive one-time OAuth setup. Every prompt falls back to a
// BUZZ_* environment variable, so it can also run unattended.
func Setup() error {
	fmt.Println("\n==========================================================")
	fmt.Println("  Buzz OAuth 2.0 Application Setup (Go)")
	fmt.Println("==========================================================")

	Section("Step 1: Buzz Server URL")
	server := strings.TrimRight(
		PromptRequired("Buzz API server URL (e.g. https://api.agilixbuzz.com)", "", EnvServerURL), "/")
	fmt.Println("  Server: " + server)

	Section("Step 2: Admin Login")
	fmt.Println("Log in as a Buzz administrator to perform the one-time setup.")
	fmt.Println("This session is used only during setup and is not stored anywhere.")
	fmt.Println()
	adminToken := AdminLogin(server)

	Section("Step 3: Application Information")
	fmt.Println("Included in the User-Agent header so Agilix support can identify your integration.")
	fmt.Println()
	contact := PromptRequired("Your contact info (name, email, or URL)", "", EnvContact)
	appName := PromptRequired("Application name (e.g. SisSync)", "", EnvAppInfo)

	Section("Step 4: Application Identity Account")
	fmt.Println("This Buzz user represents your application.  It authenticates via OAuth only.")
	fmt.Println()
	oauthUserID := getOrCreateAccount(server, adminToken)

	Section("Step 5: RSA Key Generation")
	bits := 0
	if v := os.Getenv("BUZZ_SETUP_KEY_BITS"); v != "" {
		bits, _ = strconv.Atoi(v)
	}
	if bits == 0 {
		bits, _ = strconv.Atoi(PromptRequired("RSA key size in bits", "2048", ""))
	}
	if bits == 0 {
		bits = 2048
	}
	kid := os.Getenv("BUZZ_SETUP_KID")
	if kid == "" {
		kid = PromptRequired("Key id (kid) for this key", defaultKid(), "")
	}
	if !kidRe.MatchString(kid) {
		Fail("Invalid kid '%s'. Allowed: ASCII letters, digits, -, _, .  Max 128 chars.", kid)
	}
	Info("Kid : " + kid)
	privPath, pubPath, err := GenerateKeyPair(".", bits, true)
	if err != nil {
		return err
	}
	fmt.Println("  Private key: " + privPath)

	Section("Step 6: Registering Public Key with Buzz")
	Info(fmt.Sprintf("PUT %s/api/users/%s/keys/%s", server, oauthUserID, kid))
	pub, err := os.ReadFile(pubPath)
	if err != nil {
		return err
	}
	status, body := RegisterPublicKey(server, oauthUserID, kid, string(pub), adminToken)
	if status == 204 {
		fmt.Println(" 204 OK")
	} else {
		Fail("Key registration returned HTTP %d. %s", status, body)
	}

	Section("Step 7: Writing Configuration")
	envFile, err := WriteEnv(map[string]string{
		"ServerURL":              server,
		"ContactInformation":     contact,
		"ApplicationInformation": appName,
		"OAuthUserID":            oauthUserID,
		"OAuthKid":               kid,
		"PrivateKeyPath":         privPath,
	}, EnvPath())
	if err != nil {
		return err
	}
	fmt.Println("  Written: " + envFile)

	fmt.Println("\n==========================================================")
	fmt.Println("  Setup complete!")
	fmt.Println("==========================================================")
	fmt.Println("OAuth User ID : " + oauthUserID)
	fmt.Println("Key ID (kid)  : " + kid)
	fmt.Println("Private key   : " + privPath)
	fmt.Println("Config file   : " + envFile)
	fmt.Println("\nTo test:  go run ./cmd/sample")
	fmt.Println()
	return nil
}

func getOrCreateAccount(server, adminToken string) string {
	createEnv := os.Getenv("BUZZ_SETUP_CREATE_NEW")
	doCreate := true
	if createEnv != "" {
		doCreate = strings.HasPrefix(strings.ToLower(createEnv), "y")
	} else {
		doCreate = Confirm("Create a new Application Identity account?", true)
	}

	if !doCreate {
		return PromptRequired("Existing Application Identity account userid", "", "BUZZ_SETUP_OAUTH_USER_ID")
	}

	targetDomain := os.Getenv("BUZZ_SETUP_DOMAINID")
	if targetDomain == "" {
		fmt.Print("Fetching available domains...")
		domains := listDomains(server, adminToken)
		if len(domains) > 0 {
			fmt.Print(" done\n\n")
			for i, d := range domains {
				fmt.Printf("  %2d. %-30s (id: %s)\n", i+1, d[1], d[0])
			}
			choice := PromptRequired("\nEnter domain number or type the domainid directly", "", "")
			if n, err := strconv.Atoi(choice); err == nil && n >= 1 && n <= len(domains) {
				targetDomain = domains[n-1][0]
			} else {
				targetDomain = choice
			}
		} else {
			fmt.Print(" (could not fetch domains)\n\n")
			targetDomain = PromptRequired("Domain id for the new account (e.g. //myschool or a numeric id)", "", "")
		}
	}

	username := PromptRequired("Username for the account (e.g. sis-sync)", "", "BUZZ_SETUP_APP_USERNAME")
	firstname := PromptRequired("First name (e.g. SIS)", "", "BUZZ_SETUP_APP_FIRSTNAME")
	lastname := PromptRequired("Last name (e.g. Sync)", "", "BUZZ_SETUP_APP_LASTNAME")
	email := PromptOptional("Email address", "BUZZ_SETUP_APP_EMAIL")

	user := map[string]any{
		"domainid": targetDomain, "type": "applicationidentity",
		"username": username, "firstname": firstname, "lastname": lastname,
	}
	if email != "" {
		user["email"] = email
	}

	fmt.Printf("\nCreating Application Identity account '%s'...", username)
	resp := BuzzPost(server, "createusers2", map[string]any{"requests": map[string]any{"user": []any{user}}}, adminToken)
	if ResponseCode(resp) != "OK" {
		Fail("CreateUsers2 failed (code: %s).  Response: %v", ResponseCode(resp), resp)
	}
	userID := extractCreatedUserID(resp)
	if userID == "" {
		Fail("CreateUsers2 succeeded but returned no userid.  Response: %v", resp)
	}
	fmt.Printf(" OK (userid: %s)\n", userID)
	return userID
}

func listDomains(server, token string) [][2]string {
	resp := BuzzGet(server, "getdomains", nil, token)
	if ResponseCode(resp) != "OK" {
		return nil
	}
	r, _ := resp["response"].(map[string]any)
	doms, _ := r["domains"].(map[string]any)
	var items []any
	switch t := doms["domain"].(type) {
	case []any:
		items = t
	case map[string]any:
		items = []any{t}
	}
	var out [][2]string
	for _, it := range items {
		if m, ok := it.(map[string]any); ok {
			id := valStr(m["id"])
			if id == "" {
				id = valStr(m["domainid"])
			}
			out = append(out, [2]string{id, valStr(m["name"])})
		}
	}
	return out
}

func extractCreatedUserID(resp map[string]any) string {
	r := resp
	if rr, ok := resp["response"].(map[string]any); ok {
		r = rr
	}
	responses, _ := r["responses"].(map[string]any)
	var inner map[string]any
	switch t := responses["response"].(type) {
	case []any:
		if len(t) > 0 {
			inner, _ = t[0].(map[string]any)
		}
	case map[string]any:
		inner = t
	}
	if inner == nil {
		return ""
	}
	user, _ := inner["user"].(map[string]any)
	if user == nil {
		return ""
	}
	id := valStr(user["userid"])
	if id == "" {
		id = valStr(user["id"])
	}
	return id
}

func defaultKid() string {
	now := time.Now().UTC()
	return fmt.Sprintf("%d-q%d", now.Year(), (int(now.Month())+2)/3)
}

func valStr(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", v)
	}
}
