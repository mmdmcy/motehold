package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Carried over from the Rust tests: config, router, presentation and
// component status.

// testAuthConfig uses cheap PBKDF2 settings so tests stay fast; the
// verifier reads the iterations from the hash string.
func testAuthConfig(t *testing.T, oidcEnabled bool) *authConfig {
	t.Helper()
	text, err := hashPassword("secret", 1000)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := parsePasswordHash(text)
	if err != nil {
		t.Fatal(err)
	}
	config := &authConfig{user: "motehold", passwordHash: hash, cookieSecret: []byte(strings.Repeat("\x07", 32)), cookieSecure: oidcEnabled}
	if oidcEnabled {
		config.oidc = testOIDCConfig()
	}
	return config
}

// testOIDCOnly is OIDC with no local password.
func testOIDCOnly(t *testing.T) *authConfig {
	t.Helper()
	config := testAuthConfig(t, true)
	*config = authConfig{user: config.user, cookieSecret: config.cookieSecret, cookieSecure: true, oidc: config.oidc}
	return config
}

func testOIDCConfig() *oidcConfig {
	return &oidcConfig{issuer: "https://identity.example.test", clientID: "motehold", clientSecret: "placeholder",
		redirectURL: "https://motehold.example.test/auth/oidc/callback"}
}

func testApp(t *testing.T, oidcEnabled bool) *app {
	t.Helper()
	st, err := openStore(filepath.Join(t.TempDir(), "motehold.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.close)
	return newApp(testAuthConfig(t, oidcEnabled), st)
}

type result struct {
	status int
	header http.Header
	body   string
}

func call(a *app, method, path, contentType, body string, header ...string) result {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.RemoteAddr = "192.0.2.10:1234"
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	for i := 0; i+1 < len(header); i += 2 {
		request.Header.Set(header[i], header[i+1])
	}
	recorder := httptest.NewRecorder()
	a.ServeHTTP(recorder, request)
	raw, _ := io.ReadAll(recorder.Result().Body)
	return result{recorder.Code, recorder.Result().Header, string(raw)}
}

const formType = "application/x-www-form-urlencoded"

func sessionCookieFrom(t *testing.T, r result) string {
	t.Helper()
	for _, value := range r.header.Values("Set-Cookie") {
		if strings.HasPrefix(value, "motehold_session=") {
			return strings.SplitN(value, ";", 2)[0]
		}
	}
	t.Fatal("no session cookie")
	return ""
}

func TestUnauthenticatedNonLoopbackBindNeedsExplicitOptIn(t *testing.T) {
	cases := []struct {
		bind                    string
		authDisabled, allowOpen bool
		ok                      bool
	}{
		{"127.0.0.1:8787", true, false, true},
		{"[::1]:8787", true, false, true},
		{"192.0.2.5:8787", false, false, true},
		{"192.0.2.5:8787", true, false, false},
		{"0.0.0.0:8787", true, false, false},
		{"0.0.0.0:8787", true, true, true},
		{"not-an-address", false, false, false},
	}
	for _, c := range cases {
		_, err := validateOpenBind(c.bind, c.authDisabled, c.allowOpen)
		if (err == nil) != c.ok {
			t.Errorf("validateOpenBind(%q, %v, %v) = %v", c.bind, c.authDisabled, c.allowOpen, err)
		}
	}
}

func TestRepeatedWrongPasswordsLockTheAddressOut(t *testing.T) {
	a := testApp(t, true)
	for i := 0; i < 5; i++ {
		if r := call(a, "POST", "/login", formType, "password=wrong"); r.status != http.StatusOK {
			t.Fatalf("attempt %d: %d", i, r.status)
		}
	}
	if r := call(a, "POST", "/login", formType, "password=secret"); r.status != http.StatusTooManyRequests {
		t.Fatalf("locked login: %d", r.status)
	}
	if r := call(a, "GET", "/", "", "", "Authorization", "Basic bW90ZWhvbGQ6c2VjcmV0"); r.status != http.StatusTooManyRequests {
		t.Fatalf("locked Basic: %d", r.status)
	}
}

func TestLoginRouteOffersOrganizationAndLocalBreakGlass(t *testing.T) {
	r := call(testApp(t, true), "GET", "/login", "", "")
	if r.status != http.StatusOK || !strings.Contains(r.body, "Organization login") || !strings.Contains(r.body, "Local login") {
		t.Fatalf("%d %q", r.status, r.body)
	}
}

func TestLocalBreakGlassLoginNeverContactsOIDC(t *testing.T) {
	r := call(testApp(t, true), "POST", "/login", formType, "password=secret")
	if r.status != http.StatusSeeOther {
		t.Fatal(r.status)
	}
	sessionCookieFrom(t, r)
}

func TestLogoutInvalidatesTheOpaqueSession(t *testing.T) {
	a := testApp(t, true)
	cookie := sessionCookieFrom(t, call(a, "POST", "/login", formType, "password=secret"))
	if r := call(a, "GET", "/", "", "", "Cookie", cookie); r.status != http.StatusOK {
		t.Fatalf("signed in: %d", r.status)
	}
	if r := call(a, "POST", "/logout", "", "", "Cookie", cookie); r.status != http.StatusSeeOther {
		t.Fatal(r.status)
	}
	r := call(a, "GET", "/", "", "", "Cookie", cookie)
	if r.status != http.StatusSeeOther || r.header.Get("Location") != "/login" {
		t.Fatalf("%d %q", r.status, r.header.Get("Location"))
	}
}

func TestCallbackRouteRejectsMissingFlowAndClearsFlowCookie(t *testing.T) {
	r := call(testApp(t, true), "GET", "/auth/oidc/callback", "", "")
	if r.status != http.StatusBadRequest {
		t.Fatal(r.status)
	}
	for _, value := range r.header.Values("Set-Cookie") {
		if strings.HasPrefix(value, "motehold_oidc_flow=") {
			if !strings.Contains(value, "Max-Age=0") || !strings.Contains(value, "Secure") {
				t.Fatal(value)
			}
			return
		}
	}
	t.Fatal("no flow cookie")
}

func TestLoginHTMLPreservesManagedAndBreakGlassChoices(t *testing.T) {
	managed := loginBody(true, true, "Wrong password.")
	for _, want := range []string{"Organization login", "Local login", "Wrong password."} {
		if !strings.Contains(managed, want) {
			t.Fatal(want)
		}
	}
	local := loginBody(false, true, "")
	if strings.Contains(local, "Organization login") || !strings.Contains(local, "Local login") {
		t.Fatal(local)
	}
	only := loginBody(true, false, "")
	if !strings.Contains(only, "Organization login") || strings.Contains(only, "password") || strings.Contains(only, "break-glass") {
		t.Fatal(only)
	}
}

func TestNotesHTMLPreservesRoutesAndEmptyChannelCopy(t *testing.T) {
	body := notesPage([]channel{{ID: 1, Name: "general"}}, 1, "general", nil)
	for _, want := range []string{"No messages in #general yet.", `action="/notes/channels"`, `action="/notes"`, `action="/logout"`, "[data-copy-note]"} {
		if !strings.Contains(body, want) {
			t.Fatal(want)
		}
	}
}

func TestEchoesOnlySafeCorrelationIDs(t *testing.T) {
	request := httptest.NewRequest("GET", "/", nil)
	request.Header.Set("X-Correlation-Id", "pilot:request-42")
	if got := requestCorrelationID(request); got != "pilot:request-42" {
		t.Fatal(got)
	}
	request.Header.Set("X-Correlation-Id", "unsafe/value")
	if got := requestCorrelationID(request); len(got) != 43 || strings.Trim(got, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != "" {
		t.Fatal(got)
	}
}

func TestFallbackCorrelationIDsAreRandomAndOpaque(t *testing.T) {
	request := httptest.NewRequest("GET", "/", nil)
	first, second := requestCorrelationID(request), requestCorrelationID(request)
	if first == second || len(first) != 43 {
		t.Fatal(first, second)
	}
}

// New: the answers axum gave for refused input are kept.

func TestRejectionsAnswerAsAxumDid(t *testing.T) {
	a := testApp(t, false)
	cases := []struct {
		method, path, contentType, body string
		status                          int
		want                            string
	}{
		{"GET", "/nope", "", "", 404, ""},
		{"DELETE", "/", "", "", 405, ""},
		{"POST", "/notes/abc/delete", "", "", 400, "Invalid URL: Cannot parse `abc` to a `i64`"},
		{"GET", "/notes?channel=abc", "", "", 400, "Failed to deserialize query string: channel: invalid digit found in string"},
		{"GET", "/notes?channel=", "", "", 400, "Failed to deserialize query string: channel: cannot parse integer from empty string"},
		{"GET", "/notes?channel=1&channel=2", "", "", 400, "Failed to deserialize query string: duplicate field `channel`"},
		{"POST", "/login", "", "", 415, "Form requests must have `Content-Type: application/x-www-form-urlencoded`"},
		{"POST", "/login", formType, "x=1", 422, "Failed to deserialize form body: missing field `password`"},
		{"POST", "/notes", "multipart/form-data", "", 400, "Invalid `boundary` for `multipart/form-data` request"},
	}
	for _, c := range cases {
		r := call(a, c.method, c.path, c.contentType, c.body)
		if r.status != c.status || r.body != c.want {
			t.Errorf("%s %s: %d %q", c.method, c.path, r.status, r.body)
		}
	}
	if r := call(a, "PUT", "/notes", "", ""); r.header.Get("Allow") != "GET,HEAD,POST" {
		t.Fatal(r.header)
	}
}

func TestLoginLimiterKeysByAddress(t *testing.T) {
	var limiter loginLimiter
	ip, other := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.11")
	start := time.Now()
	for i := 0; i < loginFailureLimit; i++ {
		limiter.recordFailure(ip, start)
	}
	if !limiter.isLocked(ip, start) || limiter.isLocked(other, start) {
		t.Fatal("lockout is per address")
	}
}
