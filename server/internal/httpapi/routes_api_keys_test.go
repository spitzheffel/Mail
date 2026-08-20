package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func TestAPIKeyCreateListDeleteAndGuestRejected(t *testing.T) {
	server, storage := newAPITestServer(t)
	anonymous := newCookieClient(t)
	if status, body := apiJSON(t, anonymous, http.MethodGet, server.URL+"/api/api-keys", nil); status != http.StatusUnauthorized || body["code"] != "IDENTITY_REQUIRED" {
		t.Fatalf("anonymous API key list: %d %#v", status, body)
	}

	guest := newCookieClient(t)
	if status, _ := apiJSON(t, guest, http.MethodPost, server.URL+"/api/auth/guest", map[string]any{}); status != http.StatusCreated {
		t.Fatal("guest session failed")
	}
	if status, body := apiJSON(t, guest, http.MethodGet, server.URL+"/api/api-keys", nil); status != http.StatusForbidden || body["code"] != "GUEST_SEND_DISABLED" {
		t.Fatalf("guest API key list: %d %#v", status, body)
	}

	user := newCookieClient(t)
	if status, login := apiJSON(t, user, http.MethodPost, server.URL+"/api/auth/login", map[string]any{
		"email": "admin@example.com", "password": "AdminPassword!123",
	}); status != http.StatusOK || login["authenticated"] != true {
		t.Fatalf("login failed: %d %#v", status, login)
	}

	status, created := apiJSON(t, user, http.MethodPost, server.URL+"/api/api-keys", map[string]any{"name": "n8n"})
	token, _ := created["token"].(string)
	prefix, _ := created["prefix"].(string)
	if status != http.StatusCreated || !strings.HasPrefix(token, "mlk_") || prefix == "" || created["name"] != "n8n" {
		t.Fatalf("create API key failed: %d %#v", status, created)
	}

	status, listed := apiJSON(t, user, http.MethodGet, server.URL+"/api/api-keys", nil)
	encoded, _ := json.Marshal(listed)
	if status != http.StatusOK || strings.Contains(string(encoded), token) || strings.Contains(string(encoded), `"token"`) {
		t.Fatalf("list leaked token: %d %s", status, encoded)
	}
	keys, _ := listed["keys"].([]any)
	if len(keys) != 1 || keys[0].(map[string]any)["prefix"] != prefix {
		t.Fatalf("list mismatch: %#v", listed)
	}

	bearer := newCookieClient(t)
	requestStatus, _, accounts := desktopSessionJSON(t, bearer, http.MethodGet, server.URL+"/api/accounts", token, nil)
	if requestStatus != http.StatusUnauthorized {
		t.Fatalf("raw API key bearer accessed accounts: %d %#v", requestStatus, accounts)
	}

	id := int64(created["id"].(float64))
	var stored string
	if err := storage.DB().QueryRow("SELECT token_hash FROM api_keys WHERE id=?", id).Scan(&stored); err != nil || stored == "" || stored == token {
		t.Fatalf("token was stored in plaintext: %q %v", stored, err)
	}

	path := server.URL + "/api/api-keys/" + strconv.FormatInt(id, 10)
	status, deleted := apiJSON(t, user, http.MethodDelete, path, nil)
	if status != http.StatusNoContent {
		t.Fatalf("delete failed: %d %#v", status, deleted)
	}
	status, listed = apiJSON(t, user, http.MethodGet, server.URL+"/api/api-keys", nil)
	keys, _ = listed["keys"].([]any)
	if status != http.StatusOK || len(keys) != 0 {
		t.Fatalf("deleted key still listed: %d %#v", status, listed)
	}
	status, again := apiJSON(t, user, http.MethodDelete, path, nil)
	if status != http.StatusNotFound || again["code"] != "API_KEY_NOT_FOUND" {
		t.Fatalf("repeat delete: %d %#v", status, again)
	}

	var remaining int
	if err := storage.DB().QueryRow("SELECT COUNT(*) FROM api_keys WHERE id=?", id).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("deleted API key row is still present: %d %v", remaining, err)
	}
}
