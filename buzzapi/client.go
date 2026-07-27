// Package buzzapi is a reusable client for the Buzz API.
//
// It authenticates with OAuth 2.0 JWT client credentials (RFC 6749 + RFC 7523),
// obtains and refreshes Bearer access tokens automatically, retries transient
// failures with exponential backoff, and honours rate-limit headers.
//
// The package uses only the Go standard library — no third-party dependencies.
package buzzapi

import (
	"bytes"
	"crypto"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	retriesToMake      = 5
	initialWait        = 1 * time.Second
	maxRetryWait       = 64 * time.Second
	tokenRefreshMargin = 5 * time.Minute
)

// sensitiveFields are never written to logs.
var sensitiveFields = map[string]bool{
	"token": true, "access_token": true, "refresh_token": true,
	"password": true, "client_assertion": true, "client_secret": true,
}

// noRetryStatus are HTTP status codes that must NOT be retried. Everything else
// — network errors, timeouts, 500, 502, 504, 429, 503 — is retried.
var noRetryStatus = map[int]bool{
	400: true, 401: true, 402: true, 403: true, 405: true, 406: true, 407: true,
	410: true, 411: true, 412: true, 413: true, 414: true, 415: true, 416: true,
	417: true, 421: true, 422: true, 424: true, 426: true, 428: true, 431: true, 451: true,
	501: true, 505: true, 506: true, 508: true, 510: true, 511: true,
}

// Error is returned when a Buzz API call fails or returns a non-OK response code.
type Error struct{ Message string }

func (e *Error) Error() string { return e.Message }

func newError(format string, a ...any) *Error { return &Error{Message: fmt.Sprintf(format, a...)} }

// Logger receives log messages from the client. level is one of
// "debug", "info", "warn", "error".
type Logger func(level, message string)

// Options configures optional client behaviour.
type Options struct {
	Verbose bool          // log request URLs at info level instead of debug
	Timeout time.Duration // per-request timeout (default 10 minutes)
	Logger  Logger        // defaults to writing info/warn/error to stderr
}

// Client makes requests to a Buzz API server using OAuth 2.0 JWT client credentials.
type Client struct {
	ServerURL string
	UserAgent string
	Token     string

	oauthUserID   string
	oauthKid      string
	privateKey    *rsa.PrivateKey
	tokenEndpoint string
	verbose       bool
	logger        Logger
	httpClient    *http.Client

	mu          sync.Mutex
	tokenExpiry time.Time
}

// New creates a client from an already-loaded RSA private key.
func New(serverURL, userAgent, oauthUserID, oauthKid string, privateKey *rsa.PrivateKey, opts *Options) (*Client, error) {
	if oauthUserID == "" {
		return nil, newError("oauthUserID is required")
	}
	if oauthKid == "" {
		return nil, newError("oauthKid is required")
	}
	if privateKey == nil {
		return nil, newError("privateKey is required")
	}
	if opts == nil {
		opts = &Options{}
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	logger := opts.Logger
	if logger == nil {
		logger = defaultLogger
	}
	server := strings.TrimRight(strings.TrimSpace(serverURL), "/")
	return &Client{
		ServerURL:     server,
		UserAgent:     userAgent,
		oauthUserID:   oauthUserID,
		oauthKid:      oauthKid,
		privateKey:    privateKey,
		tokenEndpoint: server + "/api/oauth/token",
		verbose:       opts.Verbose,
		logger:        logger,
		httpClient:    &http.Client{Timeout: timeout},
	}, nil
}

// FromPEMFile creates a client, loading the RSA private key from a PKCS#8 PEM file.
func FromPEMFile(serverURL, userAgent, oauthUserID, oauthKid, privateKeyPath string, opts *Options) (*Client, error) {
	key, err := LoadPrivateKeyFromPEM(privateKeyPath)
	if err != nil {
		return nil, err
	}
	return New(serverURL, userAgent, oauthUserID, oauthKid, key, opts)
}

// LoadPrivateKeyFromPEM loads an RSA private key from a PKCS#8 (or PKCS#1) PEM file.
func LoadPrivateKeyFromPEM(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, newError("could not read private key file %s: %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, newError("no PEM block found in %s", path)
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, newError("%s does not contain an RSA private key", path)
	}
	// Fall back to PKCS#1 for keys written as "RSA PRIVATE KEY".
	if rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return rsaKey, nil
	}
	return nil, newError("could not parse RSA private key from %s", path)
}

// JSONRequest makes a request to a Buzz command that returns JSON.
//
// params and jsonBody may be nil. It returns the parsed JSON object, or nil if
// the body was empty.
func (c *Client) JSONRequest(method, cmd string, params map[string]string, jsonBody any, includeToken bool) (map[string]any, error) {
	if includeToken {
		if err := c.ensureToken(); err != nil {
			return nil, err
		}
	}

	var content []byte
	if jsonBody != nil {
		b, err := json.Marshal(jsonBody)
		if err != nil {
			return nil, err
		}
		content = b
	}

	body, err := c.requestWithRetry(method, cmd, params, content, includeToken)
	if err != nil {
		return nil, err
	}
	node := parseJSON(body)
	c.traceResponse(node)

	// If the token expired or was revoked, re-authenticate and retry once.
	if includeToken && c.Token != "" && responseCode(node) == "NoAuthentication" {
		c.log("debug", `Re-authenticating because the request returned code "NoAuthentication"`)
		if err := c.authenticate(); err != nil {
			return nil, err
		}
		body, err = c.requestWithRetry(method, cmd, params, content, includeToken)
		if err != nil {
			return nil, err
		}
		node = parseJSON(body)
		c.traceResponse(node)
	}
	return node, nil
}

// VerifyResponse verifies that a Buzz JSON response indicates success. It
// returns an *Error if the response code is not "OK".
func (c *Client) VerifyResponse(node map[string]any, checkChildResponses bool) (map[string]any, error) {
	if node == nil {
		c.log("error", "Buzz API call failed. Expected response.code to be OK, found: null")
		return nil, newError("Buzz API call failed. Expected response.code to be OK, found: null")
	}
	toVerify := node
	if r := getMap(node, "response"); r != nil {
		toVerify = r
	}
	if getString(toVerify, "code") != "OK" {
		redacted, _ := json.Marshal(cloneAndRedact(node))
		c.log("error", "Buzz API call failed. Expected response.code to be OK, found: "+string(redacted))
		return nil, newError("Buzz API call failed. Expected response.code to be OK, found: %s", redacted)
	}
	if checkChildResponses {
		if responses := getMap(toVerify, "responses"); responses != nil {
			switch child := responses["response"].(type) {
			case []any:
				for _, item := range child {
					if m, ok := item.(map[string]any); ok {
						if _, err := c.VerifyResponse(m, true); err != nil {
							return nil, err
						}
					}
				}
			case map[string]any:
				if _, err := c.VerifyResponse(child, true); err != nil {
					return nil, err
				}
			}
		}
	}
	return toVerify, nil
}

// ── OAuth ────────────────────────────────────────────────────────────────────
func (c *Client) ensureToken() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Token != "" && time.Now().Before(c.tokenExpiry.Add(-tokenRefreshMargin)) {
		return nil
	}
	return c.authenticateLocked()
}

func (c *Client) authenticate() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.authenticateLocked()
}

// authenticateLocked requests a new Bearer access token. The caller must hold c.mu.
func (c *Client) authenticateLocked() error {
	c.log("info", "Requesting OAuth access token")

	retriesRemaining := retriesToMake
	baseWait := initialWait
	for {
		// A fresh assertion is built on every attempt: JWTs expire in two minutes
		// and a long backoff can push a reused assertion past its exp claim.
		assertion, err := c.buildClientAssertion()
		if err != nil {
			return err
		}
		form := url.Values{
			"grant_type":            {"client_credentials"},
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			"client_assertion":      {assertion},
		}
		req, err := http.NewRequest(http.MethodPost, c.tokenEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", c.UserAgent)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			if retriesRemaining > 0 {
				time.Sleep(waitFromRetryHeader("", baseWait))
				retriesRemaining--
				baseWait *= 2
				continue
			}
			return newError("OAuth token request failed: %v", err)
		}
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if (resp.StatusCode == 429 || resp.StatusCode == 503) && retriesRemaining > 0 {
			wait := waitFromResponse(resp.Header, baseWait)
			c.log("warn", fmt.Sprintf("OAuth token request rate-limited (%d), backing off %v, %d retries remaining", resp.StatusCode, wait, retriesRemaining))
			time.Sleep(wait)
			retriesRemaining--
			baseWait *= 2
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			if retriesRemaining > 0 && statusAllowsRetry(resp.StatusCode) {
				time.Sleep(waitFromRetryHeader(resp.Header.Get("Retry-After"), baseWait))
				retriesRemaining--
				baseWait *= 2
				continue
			}
			c.log("error", fmt.Sprintf("OAuth token request failed: %d %s", resp.StatusCode, bodyBytes))
			return newError("OAuth token request failed (HTTP %d): %s", resp.StatusCode, bodyBytes)
		}

		tokenJSON := parseJSON(bodyBytes)
		accessToken := getString(tokenJSON, "access_token")
		if accessToken == "" {
			return newError("OAuth token response did not contain an access_token.")
		}
		expiresIn := 3600
		if v := getString(tokenJSON, "expires_in"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				expiresIn = n
			}
		}
		c.Token = accessToken
		c.tokenExpiry = time.Now().Add(time.Duration(expiresIn) * time.Second)
		c.log("info", fmt.Sprintf("OAuth token obtained, expires in %ds", expiresIn))
		return nil
	}
}

// buildClientAssertion builds a signed JWT client assertion for the token
// endpoint (RFC 7523 §3), signed with RS256 (RSASSA-PKCS1-v1_5 + SHA-256).
func (c *Client) buildClientAssertion() (string, error) {
	now := time.Now().Unix()
	header := map[string]any{"alg": "RS256", "kid": c.oauthKid, "typ": "JWT"}
	payload := map[string]any{
		"iss": c.oauthUserID,   // issuer = client
		"sub": c.oauthUserID,   // subject = client (must equal iss per RFC 7523)
		"aud": c.tokenEndpoint, // audience = token endpoint URL
		"iat": now,             // issued at
		"exp": now + 120,       // expires (2-minute lifetime; max allowed is 5 min)
		"jti": randomJTI(),     // unique id — prevents replay attacks
	}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	signingInput := b64url(hb) + "." + b64url(pb)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(crand.Reader, c.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", newError("failed to sign the OAuth client assertion: %v", err)
	}
	return signingInput + "." + b64url(sig), nil
}

// ── HTTP with retry ────────────────────────────────────────────────────────────
func (c *Client) requestWithRetry(method, cmd string, params map[string]string, content []byte, includeToken bool) ([]byte, error) {
	u := c.ServerURL + "/cmd"
	if cmd != "" {
		u += "/" + cmd
	}
	if len(params) > 0 {
		q := url.Values{}
		for k, v := range params {
			q.Set(k, v)
		}
		u += "?" + q.Encode()
	}

	retriesRemaining := retriesToMake
	baseWait := initialWait
	for {
		c.traceRequest(u)

		var bodyReader io.Reader
		if content != nil {
			bodyReader = bytes.NewReader(content)
		}
		req, err := http.NewRequest(method, u, bodyReader)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", c.UserAgent)
		req.Header.Set("Accept", "application/json")
		if content != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		// OAuth always authenticates via the Authorization: Bearer header.
		if includeToken && c.Token != "" {
			req.Header.Set("Authorization", "Bearer "+c.Token)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			if retriesRemaining > 0 {
				time.Sleep(waitFromRetryHeader("", baseWait))
				retriesRemaining--
				baseWait *= 2
				continue
			}
			return nil, newError("request to %s failed: %v", u, err)
		}
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 429 || resp.StatusCode == 503 {
			if retriesRemaining > 0 {
				wait := waitFromResponse(resp.Header, baseWait)
				c.log("warn", fmt.Sprintf("Request rate/time limited (%d), backing off %v, %d retries remaining", resp.StatusCode, wait, retriesRemaining))
				time.Sleep(wait)
				retriesRemaining--
				baseWait *= 2
				continue
			}
			return nil, newError("server returned %d (rate/time limited). No retries remaining.", resp.StatusCode)
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			if retriesRemaining > 0 && statusAllowsRetry(resp.StatusCode) {
				time.Sleep(waitFromRetryHeader(resp.Header.Get("Retry-After"), baseWait))
				retriesRemaining--
				baseWait *= 2
				continue
			}
			target := cmd
			if target == "" {
				target = u
			}
			return nil, newError("request to %s failed: HTTP %d", target, resp.StatusCode)
		}
		return bodyBytes, nil
	}
}

// ── Logging ────────────────────────────────────────────────────────────────────
func (c *Client) traceRequest(u string) {
	// Bodies are never logged: request bodies may contain credentials.
	level := "debug"
	if c.verbose {
		level = "info"
	}
	c.log(level, "Request: "+redactQueryParam(u, "_token"))
}

func (c *Client) traceResponse(node map[string]any) {
	if node == nil {
		c.log("debug", "Response was empty or not JSON")
		return
	}
	text, _ := json.Marshal(cloneAndRedact(node))
	s := string(text)
	if len(s) > 1000 {
		s = s[:1000]
	}
	c.log("debug", "Response: "+s)
}

func (c *Client) log(level, message string) { c.logger(level, message) }

// ── Package helpers ────────────────────────────────────────────────────────────
func defaultLogger(level, message string) {
	if level == "debug" {
		return
	}
	fmt.Fprintf(os.Stderr, "%s: %s\n", strings.ToUpper(level), message)
}

func b64url(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func randomJTI() string {
	var b [16]byte
	if _, err := crand.Read(b[:]); err != nil {
		// Extremely unlikely; fall back to a time-based value.
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b[:])
}

func parseJSON(body []byte) map[string]any {
	if len(body) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return nil
	}
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}

func responseCode(node map[string]any) string {
	if node == nil {
		return ""
	}
	if r := getMap(node, "response"); r != nil {
		return getString(r, "code")
	}
	return getString(node, "code")
}

func getMap(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	return nil
}

// getString returns m[key] as a string, formatting numbers without exponent.
func getString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	switch v := m[key].(type) {
	case nil:
		return ""
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func statusAllowsRetry(status int) bool { return !noRetryStatus[status] }

func waitFromResponse(h http.Header, baseWait time.Duration) time.Duration {
	if d, ok := retryAfterDuration(h.Get("Retry-After")); ok && d > 0 {
		return clamp(d, baseWait, maxRetryWait)
	}
	if reset := strings.TrimSpace(h.Get("X-RateLimit-Reset")); reset != "" {
		if n, err := strconv.Atoi(reset); err == nil && n > 0 {
			return clamp(time.Duration(n)*time.Second, baseWait, maxRetryWait)
		}
	}
	return min(maxRetryWait, baseWait+jitter())
}

func waitFromRetryHeader(retryAfter string, baseWait time.Duration) time.Duration {
	if d, ok := retryAfterDuration(retryAfter); ok {
		return min(maxRetryWait, max(baseWait, d))
	}
	return min(maxRetryWait, baseWait+jitter())
}

// retryAfterDuration parses a Retry-After value (delta-seconds or an HTTP date).
func retryAfterDuration(v string) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if n, err := strconv.Atoi(v); err == nil {
		return time.Duration(n) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		d := time.Until(t)
		if d < 0 {
			d = 0
		}
		return d, true
	}
	return 0, false
}

func jitter() time.Duration { return time.Duration(1+rand.Intn(1000)) * time.Millisecond }

func clamp(v, low, high time.Duration) time.Duration { return max(low, min(high, v)) }

func redactQueryParam(uri, paramName string) string {
	q := strings.Index(uri, "?")
	if q < 0 {
		return uri
	}
	var kept []string
	for _, p := range strings.Split(uri[q+1:], "&") {
		if !strings.HasPrefix(strings.ToLower(p), strings.ToLower(paramName)+"=") {
			kept = append(kept, p)
		}
	}
	if len(kept) > 0 {
		return uri[:q] + "?" + strings.Join(kept, "&")
	}
	return uri[:q]
}

// cloneAndRedact deep-copies a JSON value, masking any sensitive field values.
func cloneAndRedact(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if sensitiveFields[k] {
				out[k] = "[REDACTED]"
			} else {
				out[k] = cloneAndRedact(val)
			}
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = cloneAndRedact(val)
		}
		return out
	default:
		return v
	}
}
