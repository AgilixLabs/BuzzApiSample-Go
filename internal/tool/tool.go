// Package tool holds shared helpers for the Buzz API sample's setup/run/cleanup
// commands (admin login, key registration, account management, configuration).
//
// These use the legacy login3 command only to obtain a short-lived admin session
// token for setup — the sample application itself never uses login3, only OAuth.
//
// Interactive prompts fall back to environment variables when set, so the
// commands can run unattended (useful for automated testing):
//
//	BUZZ_SERVER_URL, BUZZ_ADMIN_USERNAME, BUZZ_ADMIN_PASSWORD, BUZZ_ADMIN_MFA
package tool

import (
	"bufio"
	"bytes"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const httpTimeout = 60 * time.Second

// Configuration environment variable names.
const (
	EnvServerURL = "BUZZ_SERVER_URL"
	EnvContact   = "BUZZ_CONTACT_INFORMATION"
	EnvAppInfo   = "BUZZ_APPLICATION_INFORMATION"
	EnvUserID    = "BUZZ_OAUTH_USER_ID"
	EnvKid       = "BUZZ_OAUTH_KID"
	EnvKeyPath   = "BUZZ_PRIVATE_KEY_PATH"
)

// Config holds the sample's configuration.
type Config struct {
	ServerURL              string
	ContactInformation     string
	ApplicationInformation string
	OAuthUserID            string
	OAuthKid               string
	PrivateKeyPath         string
}

var httpClient = &http.Client{Timeout: httpTimeout}
var stdin = bufio.NewReader(os.Stdin)

// EnvPath returns the path to the .env file (in the working directory).
func EnvPath() string { return ".env" }

// ── Console output ─────────────────────────────────────────────────────────────
func Section(title string) {
	fmt.Printf("\n--- %s %s\n", title, strings.Repeat("-", maxInt(0, 50-len(title))))
}
func Info(msg string) { fmt.Printf("  %s\n", msg) }
func Fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "\nError: "+format+"\n", a...)
	os.Exit(1)
}

// ── Prompts (with environment-variable fallbacks) ──────────────────────────────
// ReadLine reads a line from stdin. ok is false on EOF.
func ReadLine(prompt string) (line string, ok bool) {
	if prompt != "" {
		fmt.Print(prompt)
	}
	s, err := stdin.ReadString('\n')
	if err != nil && s == "" {
		return "", false
	}
	return strings.TrimRight(s, "\r\n"), true
}

func PromptRequired(label, defaultValue, env string) string {
	if env != "" {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	for {
		suffix := ""
		if defaultValue != "" {
			suffix = " [" + defaultValue + "]"
		}
		value, ok := ReadLine(label + suffix + ": ")
		if !ok {
			if defaultValue != "" {
				return defaultValue
			}
			Fail("'%s' is required but no value was provided%s", label, envHint(env))
		}
		value = strings.TrimSpace(value)
		if value == "" {
			value = defaultValue
		}
		if value != "" {
			return value
		}
		fmt.Println("  (required)")
	}
}

func PromptOptional(label, env string) string {
	if env != "" {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	value, ok := ReadLine(label + " (optional, press Enter to skip): ")
	if !ok {
		return ""
	}
	return strings.TrimSpace(value)
}

// PromptPassword reads a value, falling back to an environment variable. Input
// is not masked (staying standard-library-only); prefer the env var for secrets
// in non-interactive use.
func PromptPassword(label, env string) string {
	if env != "" {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	value, ok := ReadLine(label + ": ")
	if !ok {
		Fail("'%s' is required but no value was provided%s", label, envHint(env))
	}
	return strings.TrimSpace(value)
}

func Confirm(label string, defaultYes bool) bool {
	suffix := "[y/N]"
	if defaultYes {
		suffix = "[Y/n]"
	}
	value, ok := ReadLine(label + " " + suffix + " ")
	if !ok || strings.TrimSpace(value) == "" {
		return defaultYes
	}
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "y")
}

func envHint(env string) string {
	if env == "" {
		return ""
	}
	return " (set " + env + ")"
}

// ── Buzz API calls ──────────────────────────────────────────────────────────
// Session tokens travel in an Authorization: Bearer header on both /cmd/* and /api/*
// endpoints.  A _token query parameter is also accepted by /cmd/*, but a credential in
// a URL is recorded by server and proxy access logs.
// Buzz returns XML unless JSON is requested via Accept.

func authHeaders(token string, extra map[string]string) map[string]string {
	h := map[string]string{"Accept": "application/json"}
	if token != "" {
		h["Authorization"] = "Bearer " + token
	}
	for k, v := range extra {
		h[k] = v
	}
	return h
}

func BuzzPost(server, cmd string, body any, token string) map[string]any {
	u := server + "/cmd/" + cmd
	data, _ := json.Marshal(body)
	_, m := httpJSON(http.MethodPost, u, data,
		authHeaders(token, map[string]string{"Content-Type": "application/json"}))
	return m
}

func BuzzGet(server, cmd string, params map[string]string, token string) map[string]any {
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	u := server + "/cmd/" + cmd
	if enc := q.Encode(); enc != "" {
		u += "?" + enc
	}
	_, m := httpJSON(http.MethodGet, u, nil, authHeaders(token, nil))
	return m
}

func RegisterPublicKey(server, userID, kid, publicKeyPEM, token string) (int, string) {
	u := fmt.Sprintf("%s/api/users/%s/keys/%s", server, userID, kid)
	status, _, raw := httpRaw(http.MethodPut, u, []byte(publicKeyPEM), map[string]string{
		"Authorization": "Bearer " + token, "Content-Type": "application/x-pem-file",
	})
	return status, raw
}

func DeletePublicKey(server, userID, kid, token string) (int, string) {
	u := fmt.Sprintf("%s/api/users/%s/keys/%s", server, userID, kid)
	status, _, raw := httpRaw(http.MethodDelete, u, nil, map[string]string{
		"Authorization": "Bearer " + token,
	})
	return status, raw
}

func httpJSON(method, u string, body []byte, headers map[string]string) (int, map[string]any) {
	status, _, raw := httpRaw(method, u, body, headers)
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err == nil {
		if m, ok := v.(map[string]any); ok {
			return status, m
		}
	}
	return status, nil
}

func httpRaw(method, u string, body []byte, headers map[string]string) (int, http.Header, string) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, u, r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  request build error for %s: %v\n", u, err)
		return 0, nil, ""
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  request error for %s: %v\n", u, err)
		return 0, nil, ""
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(raw)
}

// ResponseCode extracts response.code (or code) from a parsed Buzz response.
func ResponseCode(m map[string]any) string {
	if m == nil {
		return ""
	}
	if r, ok := m["response"].(map[string]any); ok {
		if c, ok := r["code"].(string); ok {
			return c
		}
	}
	if c, ok := m["code"].(string); ok {
		return c
	}
	return ""
}

func responseMessage(m map[string]any) string {
	inner := m
	if r, ok := m["response"].(map[string]any); ok {
		inner = r
	}
	if msg, ok := inner["message"].(string); ok {
		return msg
	}
	return ""
}

// ItemResult is the per-entity result of a multi-object command (CreateUsers2,
// DeleteUsers).  Those commands report each entity's outcome under
// response.responses.response, while the OUTER code is OK whenever the request was
// merely well formed.  A per-entity AccessDenied therefore arrives inside an "OK"
// envelope, so the outer code alone cannot tell you whether the entity was actually
// created or deleted.  Code is "" when the response carries no per-entity result.
type ItemResult struct {
	Code    string
	Message string
	UserID  string
}

func Item(m map[string]any) ItemResult {
	inner := m
	if r, ok := m["response"].(map[string]any); ok {
		inner = r
	}
	responses, ok := inner["responses"].(map[string]any)
	if !ok {
		return ItemResult{}
	}
	node, ok := responses["response"].(map[string]any)
	if !ok {
		if arr, ok := responses["response"].([]any); ok && len(arr) > 0 {
			node, _ = arr[0].(map[string]any)
		}
	}
	if node == nil {
		return ItemResult{}
	}
	res := ItemResult{}
	res.Code, _ = node["code"].(string)
	res.Message, _ = node["message"].(string)
	if u, ok := node["user"].(map[string]any); ok {
		res.UserID, _ = u["userid"].(string)
	}
	return res
}

// SecondFactorToken returns the short-lived token login3 supplies alongside
// SecondFactorRequired.  Observed shape: response.token, duplicated at
// response.body.token.  There is no "user" node on that response, so
// response.user.token (where the session token lives on a *successful* login) does not
// exist yet.  remembermfa.token is deliberately ignored: it remembers a device and
// cannot complete this login.
func SecondFactorToken(m map[string]any) string {
	inner := m
	if r, ok := m["response"].(map[string]any); ok {
		inner = r
	}
	if u, ok := inner["user"].(map[string]any); ok {
		if t, ok := u["token"].(string); ok && t != "" {
			return t
		}
	}
	if t, ok := inner["token"].(string); ok && t != "" {
		return t
	}
	if b, ok := inner["body"].(map[string]any); ok {
		if t, ok := b["token"].(string); ok && t != "" {
			return t
		}
	}
	return ""
}

// ── Admin login (login3, with optional MFA) ─────────────────────────────────────
var usernameRe = regexp.MustCompile(`^[^/]+/[^/]+$`)

func AdminLogin(server string) string {
	for {
		username := readAdminUsername()
		password := PromptPassword("Admin password", "BUZZ_ADMIN_PASSWORD")

		fmt.Print("Logging in...")
		resp := BuzzPost(server, "login3", map[string]any{
			"request": map[string]any{"cmd": "login3", "username": username, "password": password},
		}, "")
		code := ResponseCode(resp)

		// Multi-factor authentication.  login3 answers SecondFactorRequired when the
		// password was correct but the account has MFA configured, and returns a
		// short-lived token that is presented in an Authorization: Bearer header to
		// secondfactorauthenticate, which returns the real session token.  Putting the
		// token in the request body instead is ignored: AccessDenied userId='-1'.
		//   https://api.agilixbuzz.com/docs/entry/Command/Login3.md
		//   https://api.agilixbuzz.com/docs/entry/Command/SecondFactorAuthenticate.md
		if code == "SecondFactorConfigurationNowRequired" {
			fmt.Print("\n  This account must configure multi-factor authentication before it can\n")
			fmt.Print("  be used.  Complete MFA setup in Buzz, then re-run this script.\n")
			if os.Getenv("BUZZ_ADMIN_PASSWORD") != "" {
				Fail("Admin account requires multi-factor authentication setup.")
			}
			fmt.Print("  Press Ctrl+C to abort.\n\n")
			continue
		}

		if code == "SecondFactorRequired" {
			fmt.Println(" multi-factor authentication required.")
			partial := SecondFactorToken(resp)
			if partial == "" {
				fmt.Print("\n  Buzz asked for a second factor but no token could be found in its reply.\n")
				if os.Getenv("BUZZ_ADMIN_PASSWORD") != "" {
					Fail("No second-factor token was returned.")
				}
				fmt.Print("  Press Ctrl+C to abort.\n\n")
				continue
			}
			otp := PromptRequired("One-time code from your authenticator app or email", "", "BUZZ_ADMIN_MFA")
			resp = BuzzPost(server, "secondfactorauthenticate", map[string]any{
				"request": map[string]any{"cmd": "secondfactorauthenticate", "otp": otp},
			}, partial)
			code = ResponseCode(resp)
		}

		if code != "OK" {
			msg := responseMessage(resp)
			suffix := ""
			if msg != "" {
				suffix = ": " + msg
			}
			fmt.Printf("\n  Login failed (code: %s)%s\n", code, suffix)
			if os.Getenv("BUZZ_ADMIN_PASSWORD") != "" {
				Fail("Login failed with credentials from environment variables.")
			}
			fmt.Print("  Please check your credentials and try again.  Press Ctrl+C to abort.\n\n")
			continue
		}

		token := nestedString(resp, "response", "user", "token")
		if token == "" {
			token = nestedString(resp, "user", "token")
		}
		if token == "" {
			fmt.Print("\n  Login succeeded but no token was returned.  Press Ctrl+C to abort.\n\n")
			continue
		}
		fmt.Println(" OK")
		return token
	}
}

func readAdminUsername() string {
	if v := os.Getenv("BUZZ_ADMIN_USERNAME"); v != "" {
		return v
	}
	for {
		value, ok := ReadLine("Admin username (userspace/username, e.g. myschool/admin): ")
		if ok && usernameRe.MatchString(strings.TrimSpace(value)) {
			return strings.TrimSpace(value)
		}
		fmt.Println("  Username must be in userspace/username format.")
	}
}

func nestedString(m map[string]any, keys ...string) string {
	cur := m
	for i, k := range keys {
		if i == len(keys)-1 {
			if s, ok := cur[k].(string); ok {
				return s
			}
			return ""
		}
		next, ok := cur[k].(map[string]any)
		if !ok {
			return ""
		}
		cur = next
	}
	return ""
}

// ── RSA key generation ──────────────────────────────────────────────────────────
// GenerateKeyPair writes private_key.pem (0600, PKCS#8) and public_key.pem (SPKI)
// into outDir and returns their absolute paths.
func GenerateKeyPair(outDir string, bits int, overwrite bool) (string, string, error) {
	if bits < 2048 {
		return "", "", fmt.Errorf("key size must be at least 2048 bits (Buzz minimum)")
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return "", "", err
	}
	privPath, _ := filepath.Abs(filepath.Join(outDir, "private_key.pem"))
	pubPath, _ := filepath.Abs(filepath.Join(outDir, "public_key.pem"))
	if !overwrite {
		if _, err := os.Stat(privPath); err == nil {
			return "", "", fmt.Errorf("key file(s) already exist in %s", outDir)
		}
	}

	key, err := rsa.GenerateKey(crand.Reader, bits)
	if err != nil {
		return "", "", err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		return "", "", err
	}
	return privPath, pubPath, nil
}

// ── Configuration (.env) ────────────────────────────────────────────────────────
var configVars = [][2]string{
	{"ServerURL", EnvServerURL},
	{"ContactInformation", EnvContact},
	{"ApplicationInformation", EnvAppInfo},
	{"OAuthUserID", EnvUserID},
	{"OAuthKid", EnvKid},
	{"PrivateKeyPath", EnvKeyPath},
}

// LoadEnv loads KEY=VALUE lines from a .env file into the environment without
// overwriting variables already set. Returns true if a file was read.
func LoadEnv(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		i := strings.Index(line, "=")
		key := strings.TrimSpace(line[:i])
		value := strings.TrimSpace(line[i+1:])
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}
		if key != "" {
			if _, ok := os.LookupEnv(key); !ok {
				os.Setenv(key, value)
			}
		}
	}
	return true
}

// ReadConfig loads .env then reads configuration from the environment.
func ReadConfig() (Config, error) {
	LoadEnv(EnvPath())
	cfg := Config{
		ServerURL:              os.Getenv(EnvServerURL),
		ContactInformation:     os.Getenv(EnvContact),
		ApplicationInformation: os.Getenv(EnvAppInfo),
		OAuthUserID:            os.Getenv(EnvUserID),
		OAuthKid:               os.Getenv(EnvKid),
		PrivateKeyPath:         os.Getenv(EnvKeyPath),
	}
	var missing []string
	if cfg.ServerURL == "" {
		missing = append(missing, EnvServerURL)
	}
	if cfg.OAuthUserID == "" {
		missing = append(missing, EnvUserID)
	}
	if cfg.OAuthKid == "" {
		missing = append(missing, EnvKid)
	}
	if cfg.PrivateKeyPath == "" {
		missing = append(missing, EnvKeyPath)
	}
	if len(missing) > 0 {
		return cfg, fmt.Errorf("missing required configuration: %s", strings.Join(missing, ", "))
	}
	return cfg, nil
}

// WriteEnv writes configuration to a .env file. Fields map to their env names.
func WriteEnv(values map[string]string, path string) (string, error) {
	var b strings.Builder
	b.WriteString("# Buzz API sample configuration — generated by setup.  Do not commit this file.\n\n")
	for _, fv := range configVars {
		b.WriteString(fmt.Sprintf("%s=%s\n", fv[1], values[fv[0]]))
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return "", err
	}
	abs, _ := filepath.Abs(path)
	return abs, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
