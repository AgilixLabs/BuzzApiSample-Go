package buzzapi

import (
	crand "crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCheckServerURL(t *testing.T) {
	for _, bad := range []string{
		"https://api.agilixbuzz.com", "https://API.AgilixBuzz.com/", " https://api.agilixbuzz.com:443// ",
		"http://api.agilixbuzz.com/cmd",
	} {
		_, err := CheckServerURL(bad)
		var apiErr *Error
		if err == nil || !errors.As(err, &apiErr) {
			t.Fatalf("%q: expected *Error, got %v", bad, err)
		}
		if !strings.HasPrefix(err.Error(), "api.agilixbuzz.com is deprecated for API integrations") ||
			!strings.Contains(err.Error(), "https://interactiveapi.agilixbuzz.com") {
			t.Fatalf("%q: unexpected message %q", bad, err)
		}
	}
	for in, want := range map[string]string{
		"https://backgroundapi.agilixbuzz.com/":   "https://backgroundapi.agilixbuzz.com",
		" https://interactiveapi.agilixbuzz.com ": "https://interactiveapi.agilixbuzz.com",
		"https://notapi.agilixbuzz.com":           "https://notapi.agilixbuzz.com",
		"http://localhost:8080/":                  "http://localhost:8080",
		"https://example.com/api.agilixbuzz.com":  "https://example.com/api.agilixbuzz.com",
	} {
		got, err := CheckServerURL(in)
		if err != nil || got != want {
			t.Fatalf("%q: got %q, %v", in, got, err)
		}
	}
}

func newTestClient(t *testing.T, server string) *Client {
	t.Helper()
	key, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(server, "test", "1", "kid", key, &Options{Logger: func(string, string) {}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNewRefusesLegacyHost(t *testing.T) {
	key, _ := rsa.GenerateKey(crand.Reader, 2048)
	if _, err := New("https://api.agilixbuzz.com/", "test", "1", "kid", key, nil); err == nil {
		t.Fatal("expected an error")
	}
}

func TestDeprecatedCommandNotRetried(t *testing.T) {
	var calls, tokenCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/oauth/token" {
			tokenCalls.Add(1)
			w.Write([]byte(`{"access_token":"t","expires_in":3600}`))
			return
		}
		calls.Add(1)
		switch r.URL.Path {
		case "/cmd/getuser":
			w.Write([]byte(`{"response":{"code":"ApiDeprecated","message":"Use GetUser2 instead."}}`))
		case "/cmd/batch":
			w.Write([]byte(`{"response":{"code":"OK","responses":{"response":[{"code":"OK"},{"code":"ApiDeprecated","message":"Use GetUser2 instead."}]}}}`))
		case "/cmd/weird":
			w.WriteHeader(500)
			w.Write([]byte(`{"response":{"code":"ApiDeprecated","message":"Use X."}}`))
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	for _, cmd := range []string{"getuser", "batch", "weird"} {
		calls.Store(0)
		resp, err := c.JSONRequest("GET", cmd, nil, nil, true)
		if err != nil {
			t.Fatalf("%s: %v", cmd, err)
		}
		_, err = c.VerifyResponse(resp, true)
		var dep *DeprecatedError
		if !errors.As(err, &dep) {
			t.Fatalf("%s: expected *DeprecatedError, got %T %v", cmd, err, err)
		}
		var apiErr *Error
		var thr *ThrottledError
		if !errors.As(err, &apiErr) || errors.As(err, &thr) {
			t.Fatalf("%s: wrong error chain", cmd)
		}
		if !strings.HasPrefix(dep.ServerMessage, "Use ") || !strings.Contains(err.Error(), dep.ServerMessage) {
			t.Fatalf("%s: message %q / %q", cmd, dep.ServerMessage, err)
		}
		if calls.Load() != 1 {
			t.Fatalf("%s: %d calls, expected 1", cmd, calls.Load())
		}
	}
	if tokenCalls.Load() != 1 {
		t.Fatalf("%d token calls", tokenCalls.Load())
	}
	// Without child checking the batch passes.
	resp, _ := c.JSONRequest("GET", "batch", nil, nil, true)
	if _, err := c.VerifyResponse(resp, false); err != nil {
		t.Fatal(err)
	}
}

func TestOAuthUnauthorizedClientNotRetried(t *testing.T) {
	for _, status := range []int{400, 500} {
		var tokenCalls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			w.Write([]byte(`{"error":"unauthorized_client","error_description":"Use backgroundapi."}`))
		}))
		c := newTestClient(t, srv.URL)
		_, err := c.JSONRequest("GET", "getuser2", nil, nil, true)
		srv.Close()
		var dep *DeprecatedError
		if !errors.As(err, &dep) || dep.StatusCode != status || dep.ServerMessage != "Use backgroundapi." ||
			err.Error() != "Buzz refused the OAuth token request: Use backgroundapi." {
			t.Fatalf("got %T %v", err, err)
		}
		var apiErr *Error
		if !errors.As(err, &apiErr) || apiErr.StatusCode != status {
			t.Fatal("does not unwrap to *Error")
		}
		if tokenCalls.Load() != 1 {
			t.Fatalf("%d token calls, expected 1", tokenCalls.Load())
		}
	}
}
