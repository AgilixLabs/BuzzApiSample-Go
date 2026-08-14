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
		PromptRequired("Buzz API server URL (e.g. https://backgroundapi.agilixbuzz.com)", "", EnvServerURL), "/")
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
			// An empty list is normal when the admin holds no ReadDomain right anywhere,
			// or when the domain simply has no child domains.  Not an error -- just ask.
			fmt.Print(" done\n\n")
			fmt.Print("  No domains were listed for this account, so enter the target domain directly.\n")
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
	// The outer OK only means the request parsed; CreateUsers2 reports the outcome for
	// the user it created under responses.response, so a denial arrives inside an "OK"
	// envelope and must be checked separately.
	if item := Item(resp); item.Code != "" && item.Code != "OK" {
		detail := ""
		if item.Message != "" {
			detail = " - " + item.Message
		}
		if item.Code == "AccessDenied" {
			Fail("CreateUsers2 was denied (code: %s%s).\n"+
				"  The admin account needs the CreateUser right on domain %s.\n"+
				"  Grant it that right (and UpdateUser, so it can register the OAuth key), then re-run.",
				item.Code, detail, targetDomain)
		}
		Fail("CreateUsers2 failed for the requested user (code: %s%s).", item.Code, detail)
	}
	userID := extractCreatedUserID(resp)
	if userID == "" {
		Fail("CreateUsers2 succeeded but returned no userid.  Response: %v", resp)
	}
	fmt.Printf(" OK (userid: %s)\n", userID)
	return userID
}

func listDomains(server, token string) [][2]string {
	// ListDomains, not "getdomains" -- the latter is not a Buzz command and always
	// answered "Unknown API command", so this silently returned nil on every run.
	// domainid=0 means "every domain this account has ReadDomain rights on"; limit=0
	// lifts the default 100-domain cap (capped server-side at 1000 for domainid=0).
	//   https://api.agilixbuzz.com/docs/entry/Command/ListDomains.md
	resp := BuzzGet(server, "listdomains", map[string]string{"domainid": "0", "limit": "0"}, token)
	if ResponseCode(resp) != "OK" {
		return nil
	}
	// When the account can read no domains the server answers OK with "domains":{},
	// so every level has to tolerate a missing or empty node.
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
			// The Domain schema names the identifier "id"; "domainid" is what you *send*.
			out = append(out, [2]string{valStr(m["id"]), valStr(m["name"])})
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
	// The CreateUsers2 response documents this as "userid".
	return valStr(user["userid"])
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
