package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/amine123max/Mail/server/internal/mailservice"
	"github.com/amine123max/Mail/server/internal/model"
)

func TestScriptAPIKeyLeaseLifecycleAndIsolation(t *testing.T) {
	server, storage := newAPITestServer(t)
	anonymous := newCookieClient(t)
	if status, body := apiJSON(t, anonymous, http.MethodGet, server.URL+"/api/v1/keys/capabilities", nil); status != http.StatusUnauthorized || body["code"] != "API_KEY_REQUIRED" {
		t.Fatalf("anonymous capabilities: %d %#v", status, body)
	}

	guest := newCookieClient(t)
	if status, _ := apiJSON(t, guest, http.MethodPost, server.URL+"/api/auth/guest", map[string]any{}); status != http.StatusCreated {
		t.Fatal("guest session failed")
	}
	if status, body := apiJSON(t, guest, http.MethodGet, server.URL+"/api/v1/keys/capabilities", nil); status != http.StatusUnauthorized || body["code"] != "API_KEY_REQUIRED" {
		t.Fatalf("guest capabilities: %d %#v", status, body)
	}

	user := newCookieClient(t)
	if status, login := apiJSON(t, user, http.MethodPost, server.URL+"/api/auth/login", map[string]any{
		"email": "admin@example.com", "password": "AdminPassword!123",
	}); status != http.StatusOK || login["authenticated"] != true {
		t.Fatalf("login failed: %d %#v", status, login)
	}
	if status, body := apiJSON(t, user, http.MethodGet, server.URL+"/api/v1/keys/capabilities", nil); status != http.StatusUnauthorized || body["code"] != "API_KEY_REQUIRED" {
		t.Fatalf("cookie capabilities: %d %#v", status, body)
	}

	status, created := apiJSON(t, user, http.MethodPost, server.URL+"/api/api-keys", map[string]any{"name": "script"})
	token, _ := created["token"].(string)
	if status != http.StatusCreated || !strings.HasPrefix(token, "mlk_") {
		t.Fatalf("create API key failed: %d %#v", status, created)
	}

	ctx := context.Background()
	if _, err := storage.ImportAccounts(ctx, "user:1", []model.ImportedAccount{
		{Email: "one@example.invalid", Password: "p1", ClientID: "c1", RefreshToken: "refresh-token-secret-1"},
		{Email: "two@example.invalid", Password: "p2", ClientID: "c2", RefreshToken: "refresh-token-secret-2"},
	}, "skip"); err != nil {
		t.Fatal(err)
	}
	accounts, err := storage.ListAccounts(ctx, "user:1")
	if err != nil || len(accounts) != 2 {
		t.Fatalf("accounts: %#v %v", accounts, err)
	}
	if ok, err := storage.SetAccountsGroup(ctx, "user:1", []int64{accounts[0].ID, accounts[1].ID}, "register-pool"); err != nil || !ok {
		t.Fatalf("set group: %v %v", ok, err)
	}

	keyClient := newCookieClient(t)
	if status, body := desktopSessionJSONStatus(t, keyClient, http.MethodGet, server.URL+"/api/accounts", token); status != http.StatusUnauthorized {
		t.Fatalf("API key accessed accounts: %d %#v", status, body)
	}

	status, _, caps := desktopSessionJSON(t, keyClient, http.MethodGet, server.URL+"/api/v1/keys/capabilities", token, nil)
	if status != http.StatusOK || caps["version"] != float64(1) {
		t.Fatalf("capabilities: %d %#v", status, caps)
	}

	status, _, missing := desktopSessionJSON(t, keyClient, http.MethodPost, server.URL+"/api/v1/keys/inboxes/lease", token, map[string]any{"group": "", "platform": "trae"})
	if status != http.StatusBadRequest {
		t.Fatalf("empty group: %d %#v", status, missing)
	}

	status, _, leased := desktopSessionJSON(t, keyClient, http.MethodPost, server.URL+"/api/v1/keys/inboxes/lease", token, map[string]any{"group": "register-pool", "platform": "trae"})
	leaseID, _ := leased["leaseId"].(string)
	email, _ := leased["email"].(string)
	if status != http.StatusCreated || leaseID == "" || email == "" || leased["platform"] != "trae" {
		t.Fatalf("lease: %d %#v", status, leased)
	}
	encoded, _ := json.Marshal(leased)
	if strings.Contains(string(encoded), "refresh-token") || strings.Contains(string(encoded), `"accountId"`) {
		t.Fatalf("lease leaked secrets: %s", encoded)
	}

	status, _, other := desktopSessionJSON(t, keyClient, http.MethodPost, server.URL+"/api/v1/keys/inboxes/lease", token, map[string]any{"group": "register-pool", "platform": "cursor"})
	if status != http.StatusCreated || other["email"] != email {
		t.Fatalf("second platform should reuse mailbox: %d %#v", status, other)
	}

	messagesPath := server.URL + "/api/v1/keys/inboxes/" + leaseID + "/messages"
	status, _, done := desktopSessionJSON(t, keyClient, http.MethodPost, server.URL+"/api/v1/keys/inboxes/"+leaseID+"/success", token, nil)
	if status != http.StatusOK || done["status"] != "occupied" {
		t.Fatalf("success: %d %#v", status, done)
	}
	status, _, again := desktopSessionJSON(t, keyClient, http.MethodGet, messagesPath, token, nil)
	if status != http.StatusNotFound || again["code"] != "INBOX_LEASE_NOT_FOUND" {
		t.Fatalf("occupied lease still readable: %d %#v", status, again)
	}

	cursorID, _ := other["leaseId"].(string)
	status, _, released := desktopSessionJSON(t, keyClient, http.MethodPost, server.URL+"/api/v1/keys/inboxes/"+cursorID+"/release", token, map[string]any{"reason": "otp timeout"})
	if status != http.StatusOK || released["status"] != "released" {
		t.Fatalf("release: %d %#v", status, released)
	}

	status, _, reused := desktopSessionJSON(t, keyClient, http.MethodPost, server.URL+"/api/v1/keys/inboxes/lease", token, map[string]any{"group": "register-pool", "platform": "cursor"})
	if status != http.StatusCreated || reused["email"] != email {
		t.Fatalf("released platform should return to pool: %d %#v", status, reused)
	}

	status, _, nextTrae := desktopSessionJSON(t, keyClient, http.MethodPost, server.URL+"/api/v1/keys/inboxes/lease", token, map[string]any{"group": "register-pool", "platform": "trae"})
	if status != http.StatusCreated || nextTrae["email"] == email {
		t.Fatalf("occupied platform should skip mailbox: %d %#v", status, nextTrae)
	}
}

func TestScriptAPIKeyGlobalLeaseOmitsPlatformAndReleaseUnlocksAll(t *testing.T) {
	server, storage := newAPITestServer(t)
	user := newCookieClient(t)
	if status, login := apiJSON(t, user, http.MethodPost, server.URL+"/api/auth/login", map[string]any{
		"email": "admin@example.com", "password": "AdminPassword!123",
	}); status != http.StatusOK || login["authenticated"] != true {
		t.Fatalf("login failed: %d %#v", status, login)
	}
	status, created := apiJSON(t, user, http.MethodPost, server.URL+"/api/api-keys", map[string]any{"name": "script"})
	token, _ := created["token"].(string)
	if status != http.StatusCreated {
		t.Fatalf("create API key failed: %d %#v", status, created)
	}
	ctx := context.Background()
	if _, err := storage.ImportAccounts(ctx, "user:1", []model.ImportedAccount{
		{Email: "one@example.invalid", Password: "p1", ClientID: "c1", RefreshToken: "refresh-token-secret-1"},
		{Email: "two@example.invalid", Password: "p2", ClientID: "c2", RefreshToken: "refresh-token-secret-2"},
	}, "skip"); err != nil {
		t.Fatal(err)
	}
	accounts, _ := storage.ListAccounts(ctx, "user:1")
	if _, err := storage.SetAccountsGroup(ctx, "user:1", []int64{accounts[0].ID, accounts[1].ID}, "register-pool"); err != nil {
		t.Fatal(err)
	}
	keyClient := newCookieClient(t)
	status, _, global := desktopSessionJSON(t, keyClient, http.MethodPost, server.URL+"/api/v1/keys/inboxes/lease", token, map[string]any{"group": "register-pool"})
	globalID, _ := global["leaseId"].(string)
	email, _ := global["email"].(string)
	if status != http.StatusCreated || globalID == "" || email == "" || global["platform"] != nil {
		t.Fatalf("global lease: %d %#v", status, global)
	}
	status, _, named := desktopSessionJSON(t, keyClient, http.MethodPost, server.URL+"/api/v1/keys/inboxes/lease", token, map[string]any{"group": "register-pool", "platform": "trae"})
	if status != http.StatusCreated || named["email"] == email {
		t.Fatalf("named lease should skip globally occupied mailbox: %d %#v", status, named)
	}
	status, _, unlocked := desktopSessionJSON(t, keyClient, http.MethodPost, server.URL+"/api/v1/keys/inboxes/"+globalID+"/release", token, nil)
	if status != http.StatusOK || unlocked["status"] != "released" || unlocked["platform"] != nil {
		t.Fatalf("release without platform: %d %#v", status, unlocked)
	}
	status, _, reused := desktopSessionJSON(t, keyClient, http.MethodPost, server.URL+"/api/v1/keys/inboxes/lease", token, map[string]any{"group": "register-pool", "platform": "cursor"})
	if status != http.StatusCreated || reused["email"] != email {
		t.Fatalf("released global mailbox should be reusable: %d %#v", status, reused)
	}
}

func TestAccountListExposesOccupanciesAndWebReleaseFreesThem(t *testing.T) {
	server, storage := newAPITestServer(t)
	user := newCookieClient(t)
	if status, login := apiJSON(t, user, http.MethodPost, server.URL+"/api/auth/login", map[string]any{
		"email": "admin@example.com", "password": "AdminPassword!123",
	}); status != http.StatusOK || login["authenticated"] != true {
		t.Fatalf("login failed: %d %#v", status, login)
	}
	status, created := apiJSON(t, user, http.MethodPost, server.URL+"/api/api-keys", map[string]any{"name": "script"})
	token, _ := created["token"].(string)
	if status != http.StatusCreated {
		t.Fatalf("create API key failed: %d %#v", status, created)
	}
	ctx := context.Background()
	if _, err := storage.ImportAccounts(ctx, "user:1", []model.ImportedAccount{
		{Email: "one@example.invalid", Password: "p1", ClientID: "c1", RefreshToken: "refresh-token-secret-1"},
	}, "skip"); err != nil {
		t.Fatal(err)
	}
	stored, _ := storage.ListAccounts(ctx, "user:1")
	if _, err := storage.SetAccountsGroup(ctx, "user:1", []int64{stored[0].ID}, "register-pool"); err != nil {
		t.Fatal(err)
	}

	keyClient := newCookieClient(t)
	for _, platform := range []string{"trae", "cursor"} {
		if status, _, leased := desktopSessionJSON(t, keyClient, http.MethodPost, server.URL+"/api/v1/keys/inboxes/lease", token, map[string]any{
			"group": "register-pool", "platform": platform,
		}); status != http.StatusCreated || leased["platform"] != platform {
			t.Fatalf("lease %s: %d %#v", platform, status, leased)
		}
	}

	status, listed := apiJSON(t, user, http.MethodGet, server.URL+"/api/accounts", nil)
	account := listed["accounts"].([]any)[0].(map[string]any)
	occupancies, _ := account["occupancies"].([]any)
	if status != http.StatusOK || account["group"] != "register-pool" || len(occupancies) != 2 {
		t.Fatalf("account list: %d %#v", status, account)
	}
	first := occupancies[0].(map[string]any)
	if first["platform"] != "trae" || first["status"] != model.InboxOccupancyLeased {
		t.Fatalf("occupancy shape: %#v", first)
	}

	accountPath := server.URL + "/api/accounts/" + jsonNumber(account["id"])
	if status, body := apiJSON(t, user, http.MethodDelete, accountPath+"/occupancies?platform=trae", nil); status != http.StatusOK || body["released"] != float64(1) {
		t.Fatalf("release one platform: %d %#v", status, body)
	}
	status, afterOne := apiJSON(t, user, http.MethodGet, server.URL+"/api/accounts", nil)
	remaining, _ := afterOne["accounts"].([]any)[0].(map[string]any)["occupancies"].([]any)
	if status != http.StatusOK || len(remaining) != 1 || remaining[0].(map[string]any)["platform"] != "cursor" {
		t.Fatalf("after single release: %d %#v", status, remaining)
	}
	if status, body := apiJSON(t, user, http.MethodDelete, accountPath+"/occupancies", nil); status != http.StatusOK || body["released"] != float64(1) {
		t.Fatalf("release all: %d %#v", status, body)
	}

	other := newCookieClient(t)
	if status, _ := apiJSON(t, other, http.MethodPost, server.URL+"/api/auth/guest", map[string]any{}); status != http.StatusCreated {
		t.Fatal("guest session failed")
	}
	if status, body := apiJSON(t, other, http.MethodDelete, accountPath+"/occupancies", nil); status != http.StatusNotFound || body["code"] != "ACCOUNT_NOT_FOUND" {
		t.Fatalf("foreign release should not be allowed: %d %#v", status, body)
	}

	if status, _, reused := desktopSessionJSON(t, keyClient, http.MethodPost, server.URL+"/api/v1/keys/inboxes/lease", token, map[string]any{
		"group": "register-pool", "platform": "trae",
	}); status != http.StatusCreated || reused["email"] != "one@example.invalid" {
		t.Fatalf("manually released mailbox should be leasable: %d %#v", status, reused)
	}
}

func desktopSessionJSONStatus(t *testing.T, client *http.Client, method, endpoint, bearer string) (int, map[string]any) {
	t.Helper()
	status, _, body := desktopSessionJSON(t, client, method, endpoint, bearer, nil)
	return status, body
}

func TestScriptMessageSummariesOmitBodies(t *testing.T) {
	messages := scriptMessageSummaries(map[string]any{
		"messages": []mailservice.MessageSummary{{UID: 42, From: "a@b.c", Subject: "hi", Date: "now"}},
	}, "inbox")
	if len(messages) != 1 || messages[0]["id"] != "42" || messages[0]["from"] != "a@b.c" || messages[0]["folder"] != "inbox" {
		t.Fatalf("unexpected summaries: %#v", messages)
	}
}

func TestScriptJunkMessageIDsStayDisambiguatedAndSortNewestFirst(t *testing.T) {
	if got := scriptJunkMessageID("88"); got != "junk:88" {
		t.Fatalf("imap junk id: %s", got)
	}
	if got := scriptJunkMessageID("graph:abc"); got != "graph:abc" {
		t.Fatalf("graph junk id should stay global: %s", got)
	}
	uid, junkOnly := splitScriptMessageID("junk:88")
	if uid != "88" || !junkOnly {
		t.Fatalf("split junk id: %s %v", uid, junkOnly)
	}
	uid, junkOnly = splitScriptMessageID("graph:abc")
	if uid != "graph:abc" || junkOnly {
		t.Fatalf("split graph id: %s %v", uid, junkOnly)
	}
	messages := []map[string]any{
		{"id": "1", "receivedAt": "2026-01-01T00:00:00Z", "folder": "inbox"},
		{"id": "junk:2", "receivedAt": "2026-08-21T12:00:00Z", "folder": "junk"},
		{"id": "3", "receivedAt": "2026-08-21T11:00:00Z", "folder": "inbox"},
	}
	sortScriptMessages(messages)
	if messages[0]["id"] != "junk:2" || messages[1]["id"] != "3" {
		t.Fatalf("sort order: %#v", messages)
	}
}
