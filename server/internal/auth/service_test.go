package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/amine123max/Mail/server/internal/config"
	"github.com/amine123max/Mail/server/internal/secure"
	"github.com/amine123max/Mail/server/internal/store"
)

func openAuthTestService(t *testing.T, mutate func(*config.Config)) (*Service, *store.Store) {
	t.Helper()
	dataDir := t.TempDir()
	cfg := config.Config{
		DataDir:       dataDir,
		SessionSecret: strings.Repeat("session-secret-", 4),
		CookiePath:    "/",
		WebRoot:       dataDir,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	box, err := secure.New(dataDir, strings.Repeat("03", 32), false)
	if err != nil {
		t.Fatal(err)
	}
	storage, err := store.Open(dataDir, box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	return New(cfg, storage), storage
}

func TestNodeCompatiblePasswordHash(t *testing.T) {
	const password = "NodeCompatible!123"
	const nodeHash = "scrypt:AAECAwQFBgcICQoLDA0ODw:sW1COcKH7Z2BDFE6mMHuCBgIPw6OwcK45RqKR1FrA7g"
	valid, err := verifyPassword(password, nodeHash)
	if err != nil || !valid {
		t.Fatalf("Node password hash was not accepted: %v", err)
	}
	valid, err = verifyPassword("wrong-password", nodeHash)
	if err != nil || valid {
		t.Fatalf("wrong password result: valid=%v err=%v", valid, err)
	}
	generated, err := hashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	valid, err = verifyPassword(password, generated)
	if err != nil || !valid {
		t.Fatalf("generated password hash was not accepted: %v", err)
	}
}

func TestVerificationMessageLanguageAndLayout(t *testing.T) {
	for _, test := range []struct {
		language string
		want     string
	}{
		{language: "zh", want: "此验证码将在 5 分钟后失效"},
		{language: "en", want: "This code expires in 5 minutes"},
	} {
		message := BuildVerificationMessage("123456", test.language)
		if !strings.Contains(message.HTML, "123456") || !strings.Contains(message.HTML, `align="center"`) || !strings.Contains(message.HTML, test.want) {
			t.Fatalf("verification template missing expected content for %s", test.language)
		}
		for _, removed := range []string{"如果并非你本人", "安全管理 Outlook", "If this wasn't you"} {
			if strings.Contains(message.HTML, removed) {
				t.Fatalf("verification template contains removed copy %q", removed)
			}
		}
	}
	if ResolveLanguage("fr-FR, en-US;q=0.9, zh-CN;q=0.8") != "en" || ResolveLanguage("zh-CN, en;q=0.5") != "zh" {
		t.Fatal("Accept-Language resolution mismatch")
	}
}

func TestVerificationConfigurationErrorContract(t *testing.T) {
	service, _ := openAuthTestService(t, nil)
	if _, err := service.BootstrapAdministrator(context.Background(), "admin", "admin@example.com", "AdminPassword!123"); err != nil {
		t.Fatal(err)
	}
	_, err := service.RequestRegistrationCode(context.Background(), "user@example.com", "register", "en")
	var authErr *Error
	if !errors.As(err, &authErr) || authErr.Code != "VERIFICATION_EMAIL_NOT_CONFIGURED" {
		t.Fatalf("unexpected verification error: %#v", err)
	}
}

func TestVerificationRequestDoesNotRevealAccountExistence(t *testing.T) {
	service, _ := openAuthTestService(t, nil)
	if _, err := service.BootstrapAdministrator(context.Background(), "admin", "admin@example.com", "AdminPassword!123"); err != nil {
		t.Fatal(err)
	}
	unknownReset, err := service.RequestRegistrationCode(context.Background(), "missing@example.com", "reset", "en")
	if err != nil || !unknownReset.Suppressed || unknownReset.RetryAfter != int(VerificationCooldown.Seconds()) {
		t.Fatalf("unknown reset request leaked account state: result=%#v err=%v", unknownReset, err)
	}
	existingRegister, err := service.RequestRegistrationCode(context.Background(), "admin@example.com", "register", "en")
	if err != nil || !existingRegister.Suppressed || existingRegister.ExpiresIn != int(VerificationLifetime.Seconds()) {
		t.Fatalf("existing registration request leaked account state: result=%#v err=%v", existingRegister, err)
	}
}

func TestResetPasswordWithEmailVerificationCode(t *testing.T) {
	service, storage := openAuthTestService(t, nil)
	const email = "admin@example.com"
	const oldPassword = "AdminPassword!123"
	const newPassword = "ChangedPassword!456"
	user, err := service.BootstrapAdministrator(context.Background(), "admin", email, oldPassword)
	if err != nil {
		t.Fatal(err)
	}
	desktopSession, err := service.CreateDesktopSession(context.Background(), user, "password-reset-device", "Password reset test", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	claims, valid := service.readDesktopAccessToken(desktopSession.AccessToken)
	if !valid {
		t.Fatal("desktop access token was invalid before password reset")
	}
	const code = "123456"
	if err := storage.SaveEmailVerification(context.Background(), email, service.verificationHash(email, code), time.Now().Add(VerificationLifetime)); err != nil {
		t.Fatal(err)
	}
	if err := service.ResetPassword(context.Background(), email, newPassword, code); err != nil {
		t.Fatal(err)
	}
	if user, err := service.Authenticate(context.Background(), email, oldPassword); err != nil || user != nil {
		t.Fatalf("old password remained valid: user=%v err=%v", user, err)
	}
	if user, err := service.Authenticate(context.Background(), email, newPassword); err != nil || user == nil {
		t.Fatalf("new password was rejected: user=%v err=%v", user, err)
	}
	active, err := storage.DesktopSessionActive(context.Background(), claims.SessionID, claims.UserID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if active {
		t.Fatal("password reset did not revoke the desktop session")
	}
}

func TestDisabledAccountRevokesDesktopSessionAndCanRecover(t *testing.T) {
	service, storage := openAuthTestService(t, nil)
	const email = "disabled-user@example.com"
	const password = "DisabledUser!123"
	hash, err := hashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	user, err := storage.CreateUser(context.Background(), "disabled-user", hash, email, false)
	if err != nil {
		t.Fatal(err)
	}
	desktopSession, err := service.CreateDesktopSession(context.Background(), user, "disabled-device", "Disabled account test", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	claims, valid := service.readDesktopAccessToken(desktopSession.AccessToken)
	if !valid {
		t.Fatal("desktop access token was invalid before account disable")
	}
	if err := service.SetUserDisabled(context.Background(), user.ID, true); err != nil {
		t.Fatal(err)
	}
	if authenticated, err := service.Authenticate(context.Background(), email, password); err != nil || authenticated != nil {
		t.Fatalf("disabled account authenticated: user=%v err=%v", authenticated, err)
	}
	active, err := storage.DesktopSessionActive(context.Background(), claims.SessionID, claims.UserID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if active {
		t.Fatal("account disable did not revoke the desktop session")
	}
	if err := service.SetUserDisabled(context.Background(), user.ID, false); err != nil {
		t.Fatal(err)
	}
	if authenticated, err := service.Authenticate(context.Background(), email, password); err != nil || authenticated == nil {
		t.Fatalf("re-enabled account could not authenticate: user=%v err=%v", authenticated, err)
	}
}

func TestInitializeAdministratorDoesNotRequireVerificationCode(t *testing.T) {
	service, _ := openAuthTestService(t, nil)
	user, err := service.InitializeAdministrator(context.Background(), "admin", "admin@example.com", "AdminPassword!123")
	if err != nil || user == nil || !user.IsAdmin {
		t.Fatalf("administrator setup without a verification code failed: user=%v err=%v", user, err)
	}
	if _, err := service.InitializeAdministrator(context.Background(), "other", "other@example.com", "AdminPassword!123"); err == nil {
		t.Fatal("repeated administrator setup succeeded")
	}
	_, purposeErr := service.RequestRegistrationCode(context.Background(), "user@example.com", "setup", "zh")
	var authErr *Error
	if !errors.As(purposeErr, &authErr) || authErr.Code != "INVALID_VERIFICATION_PURPOSE" {
		t.Fatalf("setup verification purpose should be rejected: %#v", purposeErr)
	}
}

func TestCreateListAndDeleteAPIKeys(t *testing.T) {
	service, storage := openAuthTestService(t, nil)
	user, err := service.BootstrapAdministrator(context.Background(), "admin", "admin@example.com", "AdminPassword!123")
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateAPIKey(context.Background(), user.ID, "  n8n  ")
	if err != nil || created == nil || created.Name != "n8n" || !strings.HasPrefix(created.Token, "mlk_") || created.Prefix != created.Token[:12] {
		t.Fatalf("create API key failed: %#v %v", created, err)
	}
	exists, err := storage.APIKeyTokenHashExists(context.Background(), hashAPIKeyToken(created.Token))
	if err != nil || !exists {
		t.Fatalf("hashed API key was not stored: exists=%v err=%v", exists, err)
	}
	listed, err := service.ListAPIKeys(context.Background(), user.ID)
	if err != nil || len(listed) != 1 || listed[0].Prefix != created.Prefix {
		t.Fatalf("list API keys failed: %#v %v", listed, err)
	}
	if err := service.DeleteAPIKey(context.Background(), user.ID, created.ID); err != nil {
		t.Fatal(err)
	}
	if remaining, err := service.ListAPIKeys(context.Background(), user.ID); err != nil || len(remaining) != 0 {
		t.Fatalf("deleted API key is still listed: %#v %v", remaining, err)
	}
	if err := service.DeleteAPIKey(context.Background(), user.ID, created.ID); err == nil {
		t.Fatal("deleting a missing key succeeded")
	}
	second, err := storage.CreateUser(context.Background(), "other", user.PasswordHash, "other@example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	createdOther, err := service.CreateAPIKey(context.Background(), second.ID, "script")
	if err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteAPIKey(context.Background(), user.ID, createdOther.ID); err == nil {
		t.Fatal("cross-user API key delete succeeded")
	}
}

func TestAPIKeyIdentityAcceptsBearerAndRejectsMissing(t *testing.T) {
	service, _ := openAuthTestService(t, nil)
	user, err := service.BootstrapAdministrator(context.Background(), "admin", "admin@example.com", "AdminPassword!123")
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateAPIKey(context.Background(), user.ID, "script")
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodGet, "http://example.invalid/api/v1/keys/capabilities", nil)
	if _, _, err := service.APIKeyIdentity(context.Background(), request); err == nil {
		t.Fatal("missing bearer succeeded")
	}
	request.Header.Set("Authorization", "Bearer "+created.Token)
	identity, keyID, err := service.APIKeyIdentity(context.Background(), request)
	if err != nil || identity == nil || identity.UserID != user.ID || keyID != created.ID {
		t.Fatalf("API key identity failed: %#v %d %v", identity, keyID, err)
	}
}
