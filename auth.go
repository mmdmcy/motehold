package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	sessionCookie          = "motehold_session"
	localSessionDays       = 30
	oidcSessionHours       = 12
	loginFailureLimit      = 5
	loginFailureWindow     = 10 * time.Minute
	loginLimiterMaxEntries = 4096
)

type authConfig struct {
	user         string
	passwordHash *passwordHash
	cookieSecret []byte
	authDisabled bool
	oidc         *oidcConfig
	cookieSecure bool
}

func authConfigFromEnv() (*authConfig, error) {
	hashText, hashSet := os.LookupEnv("MOTEHOLD_PASSWORD_HASH")
	hashSet = hashSet && strings.TrimSpace(hashText) != ""
	authDisabled := envFlag("MOTEHOLD_AUTH_DISABLED", false)
	oidc, err := oidcConfigFromEnv()
	if err != nil {
		return nil, err
	}
	if err := validateAuthPolicy(hashSet, authDisabled, oidc != nil); err != nil {
		return nil, err
	}
	var hash *passwordHash
	if hashSet {
		hash, err = parsePasswordHash(hashText)
		if err != nil {
			return nil, fmt.Errorf("MOTEHOLD_PASSWORD_HASH %s; make a new one with `motehold hash-password --stdin` and set it", err)
		}
	}
	if oidc != nil && !oidc.restrictsIdentities() {
		fmt.Fprintln(os.Stderr, "warning: MOTEHOLD_OIDC_ALLOWED_SUBJECTS and MOTEHOLD_OIDC_ALLOWED_EMAILS are unset; every identity at the OIDC issuer can log in")
	}
	cookieSecure := (oidc != nil && oidc.usesSecureCookie()) || envFlag("MOTEHOLD_COOKIE_SECURE", false)
	key, err := hex.DecodeString(strings.TrimSpace(os.Getenv("MOTEHOLD_COOKIE_SECRET")))
	if err != nil || len(key) < 32 {
		key = randomBytes(32) // a development fallback: sessions end at restart
	}
	user, ok := os.LookupEnv("MOTEHOLD_USER")
	if !ok || !utf8.ValidString(user) {
		user = "motehold"
	}
	return &authConfig{
		user: user, passwordHash: hash, cookieSecret: key,
		authDisabled: authDisabled, oidc: oidc, cookieSecure: cookieSecure,
	}, nil
}

func validateAuthPolicy(hashSet, authDisabled, oidcEnabled bool) error {
	if oidcEnabled && (authDisabled || !hashSet) {
		return errors.New("managed OIDC requires MOTEHOLD_AUTH_DISABLED=0 and MOTEHOLD_PASSWORD_HASH for local break-glass login")
	}
	if !hashSet && !authDisabled {
		return errors.New("MOTEHOLD_PASSWORD_HASH is required unless MOTEHOLD_AUTH_DISABLED=1")
	}
	return nil
}

func (c *authConfig) identityMode() string {
	switch {
	case c.authDisabled:
		return "disabled"
	case c.oidc != nil:
		return "oidc+local"
	default:
		return "local"
	}
}

func (c *authConfig) secureSuffix() string {
	if c.cookieSecure {
		return "; Secure"
	}
	return ""
}

func (c *authConfig) verifyPassword(password string) bool {
	if c.authDisabled {
		return true
	}
	return c.passwordHash != nil && c.passwordHash.verify(password)
}

type access int

const (
	accessGranted   access = iota
	accessAnonymous        // no credential was presented
	accessRejected         // a Basic credential was presented and failed
)

func (a *app) access(r *http.Request) access {
	config := a.auth
	if config.authDisabled {
		return accessGranted
	}
	if value, ok := headerText(r, "Authorization"); ok {
		if raw, found := strings.CutPrefix(value, "Basic "); found {
			accepted := false
			decoded, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(raw))
			if err == nil && utf8.Valid(decoded) {
				if user, password, found := strings.Cut(string(decoded), ":"); found {
					accepted = user == config.user && config.verifyPassword(password)
				}
			}
			if accepted {
				return accessGranted
			}
			return accessRejected
		}
	}
	token, ok := cookieValue(r, sessionCookie)
	if !ok {
		return accessAnonymous
	}
	if a.verifySession(token, time.Now().Unix()) {
		return accessGranted
	}
	return accessAnonymous
}

// pageGuard sends people without a session to the login page.
func (a *app) pageGuard(r *http.Request) *response {
	switch a.access(r) {
	case accessGranted:
		return nil
	case accessRejected:
		return redirect("/login").reject()
	default:
		return redirect("/login")
	}
}

// rawGuard answers 401 for images, attachments and other raw content.
func (a *app) rawGuard(r *http.Request) *response {
	switch a.access(r) {
	case accessGranted:
		return nil
	case accessRejected:
		return text(http.StatusUnauthorized, "authentication required").reject()
	default:
		return text(http.StatusUnauthorized, "authentication required")
	}
}

func (a *app) loginPage(r *http.Request) *response {
	if a.access(r) == accessGranted {
		return redirect("/")
	}
	return html(http.StatusOK, page("Motehold Login", loginBody(a.auth.oidc != nil, "")))
}

func (a *app) loginPost(r *http.Request) *response {
	form, rejection := readForm(r)
	if rejection != nil {
		return rejection
	}
	password, rejection := form.required("password")
	if rejection != nil {
		return rejection
	}
	if !a.auth.verifyPassword(password) {
		return html(http.StatusOK, page("Motehold Login", loginBody(a.auth.oidc != nil, "Wrong password."))).reject()
	}
	cookie, err := a.createSessionCookie("local", time.Now().Unix())
	if err != nil {
		return a.authError(http.StatusInternalServerError, "Could not create a session.")
	}
	return redirect("/").cookie(cookie)
}

func (a *app) logoutPost(r *http.Request) *response {
	if token, ok := cookieValue(r, sessionCookie); ok {
		hash := a.keyedHash("session", token)
		a.store.update(func(d *storeData) error {
			d.Sessions = slices.DeleteFunc(d.Sessions, func(s session) bool { return s.TokenHash == hash })
			return nil
		})
	}
	return redirect("/login").cookie(fmt.Sprintf("%s=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax%s", sessionCookie, a.auth.secureSuffix()))
}

func (a *app) createSessionCookie(method string, now int64) (string, error) {
	token := randomToken()
	hours := int64(localSessionDays * 24)
	if method == "oidc" {
		hours = oidcSessionHours
	}
	hash := a.keyedHash("session", token)
	err := a.store.update(func(d *storeData) error {
		d.Sessions = slices.DeleteFunc(d.Sessions, func(s session) bool { return s.ExpiresAt <= now })
		d.Sessions = append(d.Sessions, session{TokenHash: hash, AuthMethod: method, ExpiresAt: now + hours*3600})
		return nil
	})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s=%s; Max-Age=%d; Path=/; HttpOnly; SameSite=Lax%s", sessionCookie, token, hours*3600, a.auth.secureSuffix()), nil
}

// verifySession checks a session token. Expired sessions are dropped with
// the next change, as the Rust service's DELETE ... WHERE expires_at <= now
// did on every check.
func (a *app) verifySession(token string, now int64) bool {
	hash := a.keyedHash("session", token)
	found := false
	a.store.view(func(d *storeData) {
		for _, s := range d.Sessions {
			if s.TokenHash == hash && s.ExpiresAt > now {
				found = true
			}
		}
	})
	return found
}

// keyedHash is HMAC-SHA256(cookie secret, purpose || value) in hex.
func (a *app) keyedHash(purpose, value string) string {
	mac := hmac.New(sha256.New, a.auth.cookieSecret)
	mac.Write([]byte(purpose))
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

func (a *app) authError(status int, message string) *response {
	return html(status, page("Motehold Login", authErrorBody(message)))
}

// loginLimiter counts rejected credentials per client address: after
// loginFailureLimit within loginFailureWindow, further attempts are refused
// until the oldest failure leaves the window.
type loginLimiter struct {
	mu       sync.Mutex
	failures map[netip.Addr][]time.Time
}

func (l *loginLimiter) isLocked(ip netip.Addr, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	entries, ok := l.failures[ip]
	if !ok {
		return false
	}
	entries = recent(entries, now)
	if len(entries) == 0 {
		delete(l.failures, ip)
		return false
	}
	l.failures[ip] = entries
	return len(entries) >= loginFailureLimit
}

func (l *loginLimiter) recordFailure(ip netip.Addr, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failures == nil {
		l.failures = map[netip.Addr][]time.Time{}
	}
	if len(l.failures) >= loginLimiterMaxEntries {
		for key, entries := range l.failures {
			if len(recent(entries, now)) == 0 {
				delete(l.failures, key)
			}
		}
	}
	l.failures[ip] = append(recent(l.failures[ip], now), now)
}

func recent(entries []time.Time, now time.Time) []time.Time {
	return slices.DeleteFunc(entries, func(at time.Time) bool { return now.Sub(at) >= loginFailureWindow })
}

// loginThrottle refuses Basic and login-form attempts from a locked-out
// address before any password hashing, and records rejected credentials.
func (a *app) loginThrottle(r *http.Request, next func() *response) *response {
	auth, _ := r.Header["Authorization"]
	isAttempt := (len(auth) > 0 && strings.HasPrefix(auth[0], "Basic ")) ||
		(r.Method == http.MethodPost && r.URL.EscapedPath() == "/login")
	if !isAttempt {
		return next()
	}
	ip := clientIP(r)
	if a.limiter.isLocked(ip, time.Now()) {
		return a.authError(http.StatusTooManyRequests, "Too many failed logins from this address. Try again later.")
	}
	res := next()
	if res.rejected {
		a.limiter.recordFailure(ip, time.Now())
	}
	return res
}

func clientIP(r *http.Request) netip.Addr {
	addrPort, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.IPv6Unspecified()
	}
	return addrPort.Addr().Unmap()
}

// headerText is the first value of a header when it is visible ASCII, as
// HeaderValue::to_str() demands.
func headerText(r *http.Request, name string) (string, bool) {
	values := r.Header[http.CanonicalHeaderKey(name)]
	if len(values) == 0 {
		return "", false
	}
	for _, c := range []byte(values[0]) {
		if !(c == '\t' || (c >= 32 && c < 127)) {
			return "", false
		}
	}
	return values[0], true
}

// cookieValue finds name in the first Cookie header, as the Rust service
// did: parts split on ';', trimmed, split at the first '='.
func cookieValue(r *http.Request, name string) (string, bool) {
	header, ok := headerText(r, "Cookie")
	if !ok {
		return "", false
	}
	for _, part := range strings.Split(header, ";") {
		key, value, found := strings.Cut(strings.TrimSpace(part), "=")
		if found && key == name {
			return value, true
		}
	}
	return "", false
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on Linux
	}
	return b
}

// randomToken is 32 random bytes in unpadded base64url (43 characters).
func randomToken() string {
	return base64.RawURLEncoding.EncodeToString(randomBytes(32))
}

func envFlag(name string, fallback bool) bool {
	value, ok := os.LookupEnv(name)
	if !ok {
		return fallback
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
