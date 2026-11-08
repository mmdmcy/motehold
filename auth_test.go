package main

import (
	"encoding/base64"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// Carried over from the Rust tests: auth policy, sessions, password hashes,
// the login limiter and the identity mode.

func TestAuthPolicy(t *testing.T) {
	if validateAuthPolicy(false, false, false) == nil {
		t.Fatal("neither a password hash nor OIDC")
	}
	if validateAuthPolicy(true, true, true) == nil || validateAuthPolicy(false, true, true) == nil {
		t.Fatal("OIDC with auth disabled")
	}
	for _, hashSet := range []bool{true, false} {
		if err := validateAuthPolicy(hashSet, false, true); err != nil {
			t.Fatal(hashSet, err)
		}
	}
	if !testAuthConfig(t, true).verifyPassword("secret") {
		t.Fatal("break-glass password")
	}
}

// With OIDC and no password hash, only the provider signs people in: the
// mode says oidc, the login page has no password form, and the login form
// and HTTP Basic credentials are refused.
func TestOIDCWithoutALocalPassword(t *testing.T) {
	t.Setenv("MOTEHOLD_PASSWORD_HASH", "")
	t.Setenv("MOTEHOLD_OIDC_ISSUER", "https://identity.example.test")
	t.Setenv("MOTEHOLD_OIDC_CLIENT_ID", "motehold")
	t.Setenv("MOTEHOLD_OIDC_CLIENT_SECRET", "placeholder")
	t.Setenv("MOTEHOLD_OIDC_REDIRECT_URL", "https://motehold.example.test/auth/oidc/callback")
	t.Setenv("MOTEHOLD_OIDC_ALLOWED_SUBJECTS", "someone")
	config, err := authConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if config.identityMode() != "oidc" || config.localLogin() || config.verifyPassword("") {
		t.Fatal(config.identityMode())
	}
	a := testApp(t, true)
	a.auth = testOIDCOnly(t)
	page := call(a, "GET", "/login", "", "")
	if page.status != 200 || !strings.Contains(page.body, "/auth/oidc/start") || strings.Contains(page.body, `name="password"`) {
		t.Fatal(page.status, page.body)
	}
	post := call(a, "POST", "/login", formType, "password=secret")
	if post.status != 403 || len(post.header.Values("Set-Cookie")) != 0 {
		t.Fatal(post.status)
	}
	basic := call(a, "GET", "/", "", "", "Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("motehold:secret")))
	if basic.status != 303 || basic.header.Get("Location") != "/login" {
		t.Fatal(basic.status, basic.header)
	}
	if status := a.componentStatus(httptest.NewRequest("GET", "/", nil)); !strings.Contains(string(status.body), `"identity_mode":"oidc"`) {
		t.Fatal(string(status.body))
	}
}

func TestOpaqueSessionsAreHashedAndExpire(t *testing.T) {
	a := testApp(t, false)
	cookie, err := a.createSessionCookie("local", 100)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.SplitN(strings.SplitN(cookie, ";", 2)[0], "=", 2)[1]
	if !a.verifySession(token, 101) {
		t.Fatal("fresh session")
	}
	a.store.view(func(d *storeData) {
		if len(d.Sessions) != 1 || d.Sessions[0].TokenHash == token {
			t.Fatal("the token itself must not be stored")
		}
	})
	if a.verifySession(token, 100+(localSessionDays+1)*86400) {
		t.Fatal("expired session")
	}
}

func TestPasswordHashRoundTrips(t *testing.T) {
	config := testAuthConfig(t, false)
	if !config.verifyPassword("secret") || config.verifyPassword("wrong") {
		t.Fatal("round trip")
	}
}

func TestLegacySHA256HashesAreNotAccepted(t *testing.T) {
	if _, err := parsePasswordHash("sha256:30313233343536373839616263646566:" + strings.Repeat("00", 32)); err == nil {
		t.Fatal("legacy sha256 hash accepted")
	}
}

func TestLoginLimiterLocksAfterRepeatedFailuresAndRecovers(t *testing.T) {
	var limiter loginLimiter
	ip, other := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.11")
	start := time.Now()
	for i := 0; i < loginFailureLimit-1; i++ {
		limiter.recordFailure(ip, start.Add(time.Duration(i)*time.Second))
	}
	if limiter.isLocked(ip, start.Add(10*time.Second)) {
		t.Fatal("locked too early")
	}
	limiter.recordFailure(ip, start.Add(10*time.Second))
	if !limiter.isLocked(ip, start.Add(11*time.Second)) || limiter.isLocked(other, start.Add(11*time.Second)) {
		t.Fatal("lock")
	}
	if !limiter.isLocked(ip, start.Add(loginFailureWindow-time.Second)) {
		t.Fatal("lock within the window")
	}
	// The oldest failures age out of the window and the address recovers.
	if limiter.isLocked(ip, start.Add(loginFailureWindow+11*time.Second)) {
		t.Fatal("recovery")
	}
}

func TestIdentityModeMatchesEffectiveAuthConfiguration(t *testing.T) {
	if got := testAuthConfig(t, false).identityMode(); got != "local" {
		t.Fatal(got)
	}
	if got := testAuthConfig(t, true).identityMode(); got != "oidc+local" {
		t.Fatal(got)
	}
	if got := testOIDCOnly(t).identityMode(); got != "oidc" {
		t.Fatal(got)
	}
	disabled := testAuthConfig(t, false)
	disabled.authDisabled = true
	if got := disabled.identityMode(); got != "disabled" {
		t.Fatal(got)
	}
}

// New: the Argon2 hashes of the Rust service are refused at start with
// the command that makes a new hash, and PBKDF2 settings are checked.

func TestArgon2HashIsRefusedWithTheFix(t *testing.T) {
	t.Setenv("MOTEHOLD_PASSWORD_HASH", "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g")
	_, err := authConfigFromEnv()
	if err == nil || !strings.Contains(err.Error(), "Argon2") || !strings.Contains(err.Error(), "hash-password --stdin") {
		t.Fatal(err)
	}
}

func TestPBKDF2HashFormat(t *testing.T) {
	text, err := hashPassword("correct horse", pbkdf2Iterations)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(text, "$pbkdf2-sha256$i=600000,l=32$") {
		t.Fatal(text)
	}
	hash, err := parsePasswordHash(text)
	if err != nil || !hash.verify("correct horse") || hash.verify("correct horse ") {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "$pbkdf2-sha256$i=0,l=32$c2FsdHNhbHQ$aGFzaA", "$pbkdf2-sha256$i=1000$c2FsdA$aGFzaA", "plain"} {
		if _, err := parsePasswordHash(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
