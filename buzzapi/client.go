// Package buzzapi is a reusable client for the Buzz API.
//
// It authenticates with OAuth 2.0 JWT client credentials (RFC 6749 + RFC 7523),
// obtains and refreshes Bearer access tokens automatically, retries transient
// failures with exponential backoff, and handles throttling and backend pressure
// (see ThrottledError).
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
	"encoding/xml"
	"errors"
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

	// maxServerDirectedWait is the longest server-directed wait (Retry-After /
	// X-RateLimit-Reset) the client will sit out before retrying. Rate-limit windows
	// are five minutes and the server adds jitter, so a Retry-After of several minutes
	// is normal. Retrying before the server says to only burns quota, so a longer
	// wait fails the request instead of retrying early.
	maxServerDirectedWait = 10 * time.Minute
)

// throttleCodes are the response codes the server uses in the XML/JSON envelope to
// say "slow down and retry later", keyed in lower case (matching is case-insensitive).
// Throttles are usually reported with HTTP 200 (the server wraps them for legacy
// clients), so the envelope code must be checked even when the HTTP status is a success.
// "TooManyRequests" is what every throttle collapses to when the server is set to report
// throttles generically; "Service Unavailable" is the code written when the server sheds
// load before a request is authenticated.
var throttleCodes = map[string]bool{
	"toomanyrequests": true, "retrylater": true, "limitexceeded": true, "ratelimit": true, "timelimit": true,
	"serveroverwhelmed": true, "backendpressure": true, "service unavailable": true, "serviceunavailable": true,
}

// sensitiveFields are never written to logs.
var sensitiveFields = map[string]bool{
	"token": true, "access_token": true, "refresh_token": true,
	"password": true, "client_assertion": true, "client_secret": true,
}

// noRetryStatus are HTTP status codes that must NOT be retried. Everything else
// — network errors, timeouts, 500, 502, 504, 429, 503 — is retried.
var noRetryStatus = map[int]bool{
	400: true, 401: true, 402: true, 403: true, 404: true, 405: true, 406: true, 407: true,
	409: true, 410: true, 411: true, 412: true, 413: true, 414: true, 415: true, 416: true,
	417: true, 421: true, 422: true, 424: true, 426: true, 428: true, 431: true, 451: true,
	501: true, 505: true, 506: true, 508: true, 510: true, 511: true,
}

// Error is returned when a Buzz API call fails or returns a non-OK response code.
type Error struct {
	Message    string
	StatusCode int // HTTP status for a failed HTTP request (429 or 503 for a throttle), else 0
}

func (e *Error) Error() string { return e.Message }

func newError(format string, a ...any) *Error { return &Error{Message: fmt.Sprintf(format, a...)} }

// ThrottledError is returned when the Buzz API throttles a request (rate limit, time
// limit, or backend pressure) and the client has run out of retries, or when items
// within a batch or multi-object request were throttled.
//
// It unwraps to an *Error, so existing errors.As(err, &buzzErr) handlers still catch it.
// StatusCode is 429 or 503 even when the server wrapped the throttle in HTTP 200.
type ThrottledError struct {
	Message    string
	StatusCode int

	// Code is the throttle code from the response envelope (for example "TimeLimit",
	// "RateLimit", "BackendPressure", or "TooManyRequests"), or the OAuth error code
	// for the token endpoint. Empty if the server sent no code.
	Code string

	// RetryAfter is how long the server asked the client to wait (Retry-After or
	// X-RateLimit-Reset), or zero if it did not say.
	RetryAfter time.Duration

	// ThrottledItemIndexes lists, for batch and multi-object requests, the indexes of
	// the items that were throttled and should be resubmitted. Items not listed here
	// completed normally (or failed for other reasons) and should not be resubmitted.
	// Empty when the whole request was throttled.
	ThrottledItemIndexes []int

	// Response is the full response envelope, including the results of any items
	// that were not throttled. Nil if there was none.
	Response map[string]any
}

func (e *ThrottledError) Error() string { return e.Message }

// Unwrap lets errors.As match a ThrottledError as an *Error.
func (e *ThrottledError) Unwrap() error { return &Error{Message: e.Message, StatusCode: e.StatusCode} }

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

	// throttledUntil is the time before which no request from this client should be
	// sent. It is set whenever the server signals throttling or backend pressure, so
	// goroutines sharing this client back off together instead of each discovering
	// the throttle separately. Guarded by throttleMu (not mu, which is held while
	// authenticating).
	throttleMu     sync.Mutex
	throttledUntil time.Time
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
// params and jsonBody may be nil. It returns the parsed JSON object (an XML
// response is converted to the same shape), or nil if the body was empty. If the
// server keeps throttling the request, it returns a *ThrottledError.
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

	node, err := c.requestWithRetry(method, cmd, params, content, includeToken)
	authenticationRejected := false
	if err != nil {
		// REST-style endpoints report an expired or revoked token as HTTP 401, possibly with no envelope.
		var apiErr *Error
		if !(includeToken && c.Token != "" && errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized) {
			return nil, err
		}
		authenticationRejected = true
	} else {
		c.traceResponse(node)
		authenticationRejected = responseCode(node) == "NoAuthentication"
	}

	// If the token expired or was revoked, re-authenticate and retry once.
	if includeToken && c.Token != "" && authenticationRejected {
		c.log("debug", `Re-authenticating because the request was rejected as unauthenticated`)
		if err := c.authenticate(); err != nil {
			return nil, err
		}
		node, err = c.requestWithRetry(method, cmd, params, content, includeToken)
		if err != nil {
			return nil, err
		}
		c.traceResponse(node)
	}
	return node, nil
}

// VerifyResponse verifies that a Buzz JSON response indicates success. It
// returns an *Error if the response code is not "OK", or a *ThrottledError if
// the code is a throttle code or (with checkChildResponses) any batch or
// multi-object items were throttled.
func (c *Client) VerifyResponse(node map[string]any, checkChildResponses bool) (map[string]any, error) {
	if node == nil {
		c.log("error", "Buzz API call failed. Expected response.code to be OK, found: null")
		return nil, newError("Buzz API call failed. Expected response.code to be OK, found: null")
	}
	toVerify := node
	if r := getMap(node, "response"); r != nil {
		toVerify = r
	}
	if code := getString(toVerify, "code"); code != "OK" {
		redacted, _ := json.Marshal(cloneAndRedact(node))
		c.log("error", "Buzz API call failed. Expected response.code to be OK, found: "+string(redacted))
		if isThrottleCode(code) {
			return nil, &ThrottledError{
				Message:    fmt.Sprintf("Buzz API call was throttled (%s): %s", code, redacted),
				StatusCode: throttleStatus(http.StatusOK, code),
				Code:       code,
				Response:   node,
			}
		}
		return nil, newError("Buzz API call failed. Expected response.code to be OK, found: %s", redacted)
	}
	if checkChildResponses {
		responses := childResponses(toVerify)

		// Batch and multi-object commands report per-item throttles under an outer OK.
		// Report them together so the caller can resubmit just those items. Throttled
		// batch items were rejected without running; a multi-object row that hit
		// BackendPressure (e.g. a database timeout) may have partially run.
		var throttledIndexes []int
		for i, item := range responses {
			if isThrottleCode(getString(item, "code")) {
				throttledIndexes = append(throttledIndexes, i)
			}
		}
		if len(throttledIndexes) > 0 {
			firstCode := getString(responses[throttledIndexes[0]], "code")
			indexes := joinInts(throttledIndexes)
			c.log("warn", fmt.Sprintf("%d of %d items were throttled (%s); resubmit items %s",
				len(throttledIndexes), len(responses), firstCode, indexes))
			return nil, &ThrottledError{
				Message: fmt.Sprintf("%d of %d items were throttled (%s). Resubmit the items at indexes %s.",
					len(throttledIndexes), len(responses), firstCode, indexes),
				StatusCode:           throttleStatus(http.StatusOK, firstCode),
				Code:                 firstCode,
				ThrottledItemIndexes: throttledIndexes,
				Response:             node,
			}
		}

		for _, item := range responses {
			if item != nil {
				if _, err := c.VerifyResponse(item, true); err != nil {
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
		// Wait out any client-wide throttle window before building the assertion,
		// so a long wait cannot push it past its exp claim.
		c.waitForThrottleWindow()

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

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			// The token endpoint answers with RFC 6749 errors rather than the Buzz envelope:
			// rate limits and backend pressure are 429/503 with error "temporarily_unavailable" and Retry-After.
			errorJSON, _ := parseEnvelope(bodyBytes, resp.Header.Get("Content-Type"))
			oauthError := getString(errorJSON, "error")
			if resp.StatusCode == 429 || resp.StatusCode == 503 || oauthError == "temporarily_unavailable" {
				serverWait, hasServerWait := serverDirectedWait(resp.Header)
				wait := throttleWait(serverWait, hasServerWait, baseWait)
				if retriesRemaining > 0 && wait <= maxServerDirectedWait {
					c.log("warn", fmt.Sprintf("OAuth token request throttled (%d, %s), backing off %v, %d retries remaining",
						resp.StatusCode, oauthError, wait, retriesRemaining))
					c.extendThrottleWindow(wait)
					retriesRemaining--
					baseWait *= 2
					continue // the throttle window is waited out at the top of the loop
				}
				c.extendThrottleWindow(min(wait, maxServerDirectedWait))
				return &ThrottledError{
					Message:    fmt.Sprintf("OAuth token request was throttled (HTTP %d): %s", resp.StatusCode, bodyBytes),
					StatusCode: throttleStatus(resp.StatusCode, ""),
					Code:       oauthError,
					RetryAfter: serverWait,
				}
			}
			if retriesRemaining > 0 && statusAllowsRetry(resp.StatusCode) {
				time.Sleep(waitFromRetryHeader(resp.Header.Get("Retry-After"), baseWait))
				retriesRemaining--
				baseWait *= 2
				continue
			}
			c.log("error", fmt.Sprintf("OAuth token request failed: %d %s", resp.StatusCode, bodyBytes))
			return &Error{
				Message:    fmt.Sprintf("OAuth token request failed (HTTP %d): %s", resp.StatusCode, bodyBytes),
				StatusCode: resp.StatusCode,
			}
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

// requestWithRetry sends a request, retrying transient failures, and returns the
// parsed response envelope (XML or JSON, normalized to the JSON shape). Throttling
// is recognized from the HTTP status (429/503) or from the envelope code, since the
// server usually reports throttles as HTTP 200 with a code like "TimeLimit" or
// "BackendPressure" in the body.
func (c *Client) requestWithRetry(method, cmd string, params map[string]string, content []byte, includeToken bool) (map[string]any, error) {
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
	target := cmd
	if target == "" {
		target = u
	}

	retriesRemaining := retriesToMake
	baseWait := initialWait
	for {
		c.waitForThrottleWindow()
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

		// Parse strictly on success; on failure the envelope is optional (it may be an
		// HTML error page from a proxy). A success body that fails to parse is not
		// retried: the server already ran the command, and resending a mutation (or a
		// batch) could repeat it.
		success := resp.StatusCode >= 200 && resp.StatusCode < 300
		envelope, parseErr := parseEnvelope(bodyBytes, resp.Header.Get("Content-Type"))
		if parseErr != nil {
			if success {
				return nil, newError("could not parse the response from %s: %v", target, parseErr)
			}
			envelope = nil
		}
		code := responseCode(envelope)

		// API time/rate limiting and backend pressure: HTTP 429/503 (REST-style), or an
		// envelope throttle code (usually with HTTP 200). Retry-After is sent either way;
		// X-RateLimit-Reset (seconds until the window resets) is the fallback.
		if resp.StatusCode == 429 || resp.StatusCode == 503 || isThrottleCode(code) {
			serverWait, hasServerWait := serverDirectedWait(resp.Header)
			wait := throttleWait(serverWait, hasServerWait, baseWait)
			message := getString(getMap(envelope, "response"), "message")
			if retriesRemaining > 0 && wait <= maxServerDirectedWait {
				c.log("warn", fmt.Sprintf("Request throttled (HTTP %d, code %q, message %q, pressure %q %q), backing off %v, %d retries remaining",
					resp.StatusCode, code, message, resp.Header.Get("X-Backend-Pressure-Service"), resp.Header.Get("X-Backend-Pressure-Level"),
					wait, retriesRemaining))
				c.extendThrottleWindow(wait)
				retriesRemaining--
				baseWait *= 2
				continue // the throttle window is waited out at the top of the loop
			}
			c.extendThrottleWindow(min(wait, maxServerDirectedWait))
			reason := "no retries remaining"
			if retriesRemaining > 0 {
				reason = fmt.Sprintf("server asked to wait %ds, longer than the %ds limit",
					int(wait/time.Second), int(maxServerDirectedWait/time.Second))
			}
			codeText := code
			if codeText == "" {
				codeText = "none"
			}
			return nil, &ThrottledError{
				Message: fmt.Sprintf("Buzz API request was throttled (HTTP %d, code %s): %s (%s)",
					resp.StatusCode, codeText, message, reason),
				StatusCode: throttleStatus(resp.StatusCode, code),
				Code:       code,
				RetryAfter: serverWait,
				Response:   envelope,
			}
		}

		if success {
			c.extendThrottleWindowForThrottledItems(envelope, resp.Header)
			return envelope, nil
		}

		// A REST-style error status with an envelope (e.g. 400 BadRequest, 404
		// ResourceNotFound): return it so the caller sees the server's code and message,
		// just as it would for the same error wrapped in HTTP 200. 401 is returned as an
		// error instead so JSONRequest re-authenticates whether or not an envelope came with it.
		if code != "" && !statusAllowsRetry(resp.StatusCode) && resp.StatusCode != http.StatusUnauthorized {
			return envelope, nil
		}

		if retriesRemaining > 0 && statusAllowsRetry(resp.StatusCode) {
			time.Sleep(waitFromRetryHeader(resp.Header.Get("Retry-After"), baseWait))
			retriesRemaining--
			baseWait *= 2
			continue
		}
		codeSuffix := ""
		if code != "" {
			codeSuffix = fmt.Sprintf(" (code %s)", code)
		}
		return nil, &Error{
			Message:    fmt.Sprintf("request to %s failed: HTTP %d%s", target, resp.StatusCode, codeSuffix),
			StatusCode: resp.StatusCode,
		}
	}
}

// ── Throttling ─────────────────────────────────────────────────────────────────

// extendThrottleWindowForThrottledItems backs off the whole client when a successful
// batch or multi-object response contains throttled items, so resubmitting them (and
// any other requests sharing this client) waits as the server asked.
func (c *Client) extendThrottleWindowForThrottledItems(envelope map[string]any, h http.Header) {
	response := envelope
	if r := getMap(envelope, "response"); r != nil {
		response = r
	}
	throttled := countThrottledItems(response)
	if throttled == 0 {
		return
	}
	serverWait, hasServerWait := serverDirectedWait(h)
	wait := min(throttleWait(serverWait, hasServerWait, initialWait), maxServerDirectedWait)
	c.log("warn", fmt.Sprintf("%d items in the response were throttled; backing off %v before the next request", throttled, wait))
	c.extendThrottleWindow(wait)
}

// extendThrottleWindow moves the client-wide throttle window out to at least wait
// from now. It never moves the window backward.
func (c *Client) extendThrottleWindow(wait time.Duration) {
	until := time.Now().Add(wait)
	c.throttleMu.Lock()
	defer c.throttleMu.Unlock()
	if until.After(c.throttledUntil) {
		c.throttledUntil = until
	}
}

// waitForThrottleWindow blocks until the client-wide throttle window has passed.
func (c *Client) waitForThrottleWindow() {
	for {
		c.throttleMu.Lock()
		remaining := time.Until(c.throttledUntil)
		c.throttleMu.Unlock()
		if remaining <= 0 {
			return
		}
		c.log("debug", fmt.Sprintf("Waiting %v for the server's throttle window to pass", remaining))
		time.Sleep(remaining)
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

// parseEnvelope parses a response body as the XML or JSON envelope. The server
// returns XML unless JSON is requested, and some error paths may ignore the Accept
// header, so XML is converted to the equivalent JSON shape: attributes and child
// elements become properties, repeated elements become arrays, and text content
// becomes "$value". It returns nil for an empty body or a JSON value that is not
// an object, and an error if the body is not valid XML or JSON.
func parseEnvelope(body []byte, contentType string) (map[string]any, error) {
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF}) // UTF-8 byte order mark
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, nil
	}
	if !strings.Contains(strings.ToLower(contentType), "xml") && trimmed[0] != '<' {
		var v any
		if err := json.Unmarshal(body, &v); err != nil {
			return nil, err
		}
		m, _ := v.(map[string]any)
		return m, nil
	}

	d := xml.NewDecoder(bytes.NewReader(body))
	var root map[string]any
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if root != nil {
				return nil, errors.New("XML response has more than one root element")
			}
			obj, err := xmlElementToMap(d, t)
			if err != nil {
				return nil, err
			}
			root = map[string]any{t.Name.Local: obj}
		case xml.CharData:
			if len(bytes.TrimSpace(t)) > 0 {
				return nil, errors.New("XML response has text outside the root element")
			}
		}
	}
	if root == nil {
		return nil, errors.New("XML response has no root element")
	}
	return root, nil
}

// xmlElementToMap converts the element started by start (whose tokens are read
// from d up to its end element) to the JSON shape described on parseEnvelope.
func xmlElementToMap(d *xml.Decoder, start xml.StartElement) (map[string]any, error) {
	obj := map[string]any{}
	for _, a := range start.Attr {
		if a.Name.Space == "xmlns" || (a.Name.Space == "" && a.Name.Local == "xmlns") {
			continue // namespace declaration
		}
		obj[a.Name.Local] = a.Value
	}
	var names []string // child element names, in first-seen order
	children := map[string][]any{}
	var text strings.Builder
	for {
		tok, err := d.Token()
		if err != nil {
			return nil, err // io.EOF here means the element was never closed
		}
		switch t := tok.(type) {
		case xml.StartElement:
			child, err := xmlElementToMap(d, t)
			if err != nil {
				return nil, err
			}
			if _, seen := children[t.Name.Local]; !seen {
				names = append(names, t.Name.Local)
			}
			children[t.Name.Local] = append(children[t.Name.Local], child)
		case xml.CharData:
			text.Write(t)
		case xml.EndElement:
			for _, name := range names {
				if group := children[name]; len(group) == 1 {
					obj[name] = group[0]
				} else {
					obj[name] = group
				}
			}
			if strings.TrimSpace(text.String()) != "" {
				obj["$value"] = text.String()
			}
			return obj, nil
		}
	}
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

// serverDirectedWait reads the wait the server asked for: Retry-After (delta-seconds
// or HTTP date) first, then X-RateLimit-Reset, which Buzz sends as seconds until the
// rate-limit window resets (not a Unix time). The server sends these on throttled
// responses whether the HTTP status is 200 or 429/503. ok is false if it gave none.
func serverDirectedWait(h http.Header) (wait time.Duration, ok bool) {
	if d, ok := retryAfterDuration(h.Get("Retry-After")); ok && d > 0 {
		return d, true
	}
	if n, err := strconv.Atoi(strings.TrimSpace(h.Get("X-RateLimit-Reset"))); err == nil && n > 0 {
		return time.Duration(n) * time.Second, true
	}
	return 0, false
}

// throttleWait computes how long to back off from a throttle: the server-directed
// wait if there is one (never less than the current exponential base), otherwise
// exponential backoff with jitter. A server-directed wait is not capped here; the
// caller compares it with maxServerDirectedWait rather than retrying before the
// server said to.
func throttleWait(serverWait time.Duration, hasServerWait bool, baseWait time.Duration) time.Duration {
	if hasServerWait {
		return max(serverWait, baseWait)
	}
	return min(maxRetryWait, baseWait+jitter())
}

// throttleStatus is the HTTP status to report for a throttle: the real one when the
// server sent 429/503, otherwise the status the envelope code stands for (the server
// wraps these in HTTP 200 for legacy clients).
func throttleStatus(status int, code string) int {
	if status == 429 || status == 503 {
		return status
	}
	switch strings.ToLower(code) {
	case "serveroverwhelmed", "backendpressure", "service unavailable", "serviceunavailable":
		return 503
	}
	return 429
}

func isThrottleCode(code string) bool { return throttleCodes[strings.ToLower(code)] }

// childResponses returns the per-item results of a batch or multi-object command
// (responses.response). JSON always gives an array; a single item converted from
// XML is an object. Non-object items are returned as nil so indexes line up.
func childResponses(response map[string]any) []map[string]any {
	switch items := getMap(response, "responses")["response"].(type) {
	case []any:
		out := make([]map[string]any, len(items))
		for i, item := range items {
			out[i], _ = item.(map[string]any)
		}
		return out
	case map[string]any:
		return []map[string]any{items}
	}
	return nil
}

// countThrottledItems counts throttled items at any depth, since a batch item can
// itself be a multi-object command with per-row results.
func countThrottledItems(response map[string]any) int {
	n := 0
	for _, item := range childResponses(response) {
		if isThrottleCode(getString(item, "code")) {
			n++
		}
		n += countThrottledItems(item)
	}
	return n
}

func joinInts(values []int) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ",")
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
