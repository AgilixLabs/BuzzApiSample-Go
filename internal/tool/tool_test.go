package tool

import (
	"encoding/json"
	"testing"
)

func TestDeprecatedMessage(t *testing.T) {
	const fallback = "Buzz refused this request because it uses a deprecated API."
	cases := []struct {
		name, body, message string
		refused             bool
	}{
		{"login3 refused", `{"response":{"code":"ApiDeprecated","message":"Use OAuth instead."}}`, "Use OAuth instead.", true},
		{"no message", `{"response":{"code":"ApiDeprecated"}}`, fallback, true},
		{"item refused", `{"response":{"code":"OK","responses":{"response":[{"code":"ApiDeprecated","message":"Use CreateUsers2."}]}}}`,
			"Use CreateUsers2.", true},
		{"ok", `{"response":{"code":"OK","responses":{"response":[{"code":"OK"}]}}}`, "", false},
		{"other failure", `{"response":{"code":"InvalidCredentials","message":"Invalid username or password."}}`, "", false},
		{"no response", `null`, "", false},
	}
	for _, c := range cases {
		var m map[string]any
		if err := json.Unmarshal([]byte(c.body), &m); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		message, refused := deprecatedMessage(m)
		if message != c.message || refused != c.refused {
			t.Errorf("%s: got (%q, %v), want (%q, %v)", c.name, message, refused, c.message, c.refused)
		}
	}
}
