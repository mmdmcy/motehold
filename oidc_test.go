package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Carried over from the Rust tests, plus a whole sign-in against a fake
// provider for each signature algorithm and each refusal the crate made.

func ptr(s string) *string { return &s }

func TestConfigurationIsAllOrNone(t *testing.T) {
	if config, err := oidcConfigFromValues(nil, nil, nil, nil); config != nil || err != nil {
		t.Fatal(config, err)
	}
	if _, err := oidcConfigFromValues(ptr("https://identity.example.test"), ptr("client"), nil, ptr("https://app.example.test/auth/oidc/callback")); err == nil {
		t.Fatal("partial configuration accepted")
	}
}

func TestURLsRequireHTTPSOrLoopbackHTTP(t *testing.T) {
	ok := func(name, raw string, callback bool) bool { return validateOIDCURL(name, raw, callback) == nil }
	if !ok("issuer", "https://identity.example.test", false) || !ok("issuer", "http://127.0.0.1:8080", false) {
		t.Fatal("valid issuer refused")
	}
	if ok("issuer", "http://identity.example.test", false) {
		t.Fatal("plain HTTP issuer accepted")
	}
	if !ok("redirect", "http://localhost:8787/auth/oidc/callback", true) || ok("redirect", "javascript:alert(1)", true) {
		t.Fatal("redirect rules")
	}
	for _, bad := range []string{"https://identity.example.test/?x=1", "https://identity.example.test/#x", "https://user:pw@identity.example.test", "http://[::1]:8080"} {
		if ok("issuer", bad, false) {
			t.Errorf("accepted %q", bad)
		}
	}
	if ok("redirect", "https://app.example.test/callback", true) {
		t.Fatal("wrong callback path accepted")
	}
}

func TestAllowlistRestrictsIdentitiesOnlyWhenConfigured(t *testing.T) {
	open := testOIDCConfig()
	if open.restrictsIdentities() || !open.permits("anyone", nil) {
		t.Fatal("open config")
	}
	restricted := testOIDCConfig().withAllowlist([]string{"sub-1"}, []string{"Rei@Example.test"})
	if !restricted.restrictsIdentities() || !restricted.permits("sub-1", nil) || !restricted.permits("sub-2", ptr("rei@example.test")) {
		t.Fatal("allowed identities")
	}
	if restricted.permits("sub-2", ptr("other@example.test")) || restricted.permits("sub-2", nil) {
		t.Fatal("refused identities")
	}
}

func TestUppercaseHTTPSRedirectStillUsesASecureCookie(t *testing.T) {
	config, err := oidcConfigFromValues(ptr("https://identity.example.test"), ptr("client"), ptr("secret"), ptr("HTTPS://app.example.test/auth/oidc/callback"))
	if err != nil || !config.usesSecureCookie() {
		t.Fatal(err)
	}
}

func TestTokenAuthMethodFollowsProviderMetadata(t *testing.T) {
	both := []string{"client_secret_basic", "client_secret_post"}
	basicOnly := []string{"client_secret_basic"}
	jwtOnly := []string{"private_key_jwt"}
	if post, err := selectTokenAuthMethod(&both); !post || err != nil {
		t.Fatal("post preferred")
	}
	if post, err := selectTokenAuthMethod(&basicOnly); post || err != nil {
		t.Fatal("basic")
	}
	if post, err := selectTokenAuthMethod(nil); post || err != nil {
		t.Fatal("basic by default")
	}
	if _, err := selectTokenAuthMethod(&jwtOnly); err == nil {
		t.Fatal("unsupported method accepted")
	}
}

func TestDiscoveredEndpointsRequireHTTPSOrLoopbackHTTP(t *testing.T) {
	if validateServiceEndpoint("authorization endpoint", "https://identity.example.test/authorize") != nil ||
		validateServiceEndpoint("token endpoint", "http://127.0.0.1:8080/token") != nil {
		t.Fatal("valid endpoints refused")
	}
	if validateServiceEndpoint("JWKS endpoint", "http://identity.example.test/jwks.json") == nil ||
		validateServiceEndpoint("userinfo endpoint", "https://user:password@identity.example.test/userinfo") == nil {
		t.Fatal("bad endpoints accepted")
	}
}

func TestPendingStateNonceAndBrowserBindingAreOneTimeAndExpire(t *testing.T) {
	a := testApp(t, true)
	a.storePendingFlow("state", "browser-a", "nonce", "verifier", 100)
	if flow, _ := a.takePendingFlow("state", "browser-b", 101); flow != nil {
		t.Fatal("other browser")
	}
	a.storePendingFlow("state-2", "browser-a", "nonce", "verifier", 100)
	flow, _ := a.takePendingFlow("state-2", "browser-a", 101)
	if flow == nil || flow.Nonce != "nonce" || flow.PKCEVerifier != "verifier" {
		t.Fatal(flow)
	}
	if again, _ := a.takePendingFlow("state-2", "browser-a", 102); again != nil {
		t.Fatal("used twice")
	}
	a.storePendingFlow("old", "browser", "nonce", "verifier", 100)
	if flow, _ := a.takePendingFlow("old", "browser", 100+(pendingFlowMinutes+1)*60); flow != nil {
		t.Fatal("expired flow")
	}
}

// fakeProvider is an OIDC provider on loopback HTTP that signs ID tokens
// with the chosen algorithm.
type fakeProvider struct {
	server     *httptest.Server
	alg        string
	edKey      ed25519.PrivateKey
	rsaKey     *rsa.PrivateKey
	ecKey      *ecdsa.PrivateKey
	authMethod []string
	claims     func(nonce string) map[string]any
	header     map[string]any
	tamper     func(token string) string
	answerBody  func(idToken string) string
	lastForm   url.Values
	lastAuth   string
	nonce      string
}

func newFakeProvider(t *testing.T, alg string) *fakeProvider {
	t.Helper()
	p := &fakeProvider{alg: alg, authMethod: []string{"client_secret_post", "client_secret_basic"}}
	_, p.edKey, _ = ed25519.GenerateKey(rand.Reader)
	p.rsaKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	p.ecKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p.server = httptest.NewServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.server.Close)
	p.claims = func(nonce string) map[string]any {
		return map[string]any{"iss": p.server.URL, "aud": "motehold", "sub": "sub-1", "email": "rei@example.test",
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": nonce}
	}
	return p
}

// answerWithout is a token answer that ends before its ID token.
func answerWithout(field string) string {
	if field == "id_token" {
		return "{\"access_token\":\"a\",\"token_type\":\"Bearer\"}"
	}
	return "{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"id_token\":\""
}

func b64(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

func (p *fakeProvider) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": p.server.URL, "authorization_endpoint": p.server.URL + "/authorize",
			"token_endpoint": p.server.URL + "/token", "jwks_uri": p.server.URL + "/jwks",
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
			"id_token_signing_alg_values_supported": []string{p.alg}, "token_endpoint_auth_methods_supported": p.authMethod,
		})
	case "/jwks":
		e := big.NewInt(int64(p.rsaKey.E)).Bytes()
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{
			{"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA", "kid": "ed", "x": b64(p.edKey.Public().(ed25519.PublicKey))},
			{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "rsa", "n": b64(p.rsaKey.N.Bytes()), "e": b64(e)},
			{"kty": "EC", "crv": "P-256", "use": "sig", "kid": "ec", "x": b64(p.ecKey.X.FillBytes(make([]byte, 32))), "y": b64(p.ecKey.Y.FillBytes(make([]byte, 32)))},
		}})
	case "/token":
		r.ParseForm()
		p.lastForm, p.lastAuth = r.PostForm, r.Header.Get("Authorization")
		signed := p.sign(p.claims(p.nonce))
		if p.tamper != nil {
			signed = p.tamper(signed)
		}
		body := `{"access_token":"access","token_type":"Bearer","id_token":"` + signed + `"}`
		if p.answerBody != nil {
			body = p.answerBody(signed)
		}
		w.Write([]byte(body))
	default:
		http.NotFound(w, r)
	}
}

func (p *fakeProvider) sign(claims map[string]any) string {
	kids := map[string]string{"EdDSA": "ed", "RS256": "rsa", "ES256": "ec", "HS256": ""}
	header := map[string]any{"alg": p.alg, "typ": "JWT"}
	if kids[p.alg] != "" {
		header["kid"] = kids[p.alg]
	}
	for k, v := range p.header {
		header[k] = v
	}
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	input := b64(h) + "." + b64(c)
	digest := sha256.Sum256([]byte(input))
	var signature []byte
	switch p.alg {
	case "EdDSA":
		signature = ed25519.Sign(p.edKey, []byte(input))
	case "RS256":
		signature, _ = rsa.SignPKCS1v15(rand.Reader, p.rsaKey, 5, digest[:]) // crypto.SHA256
	case "ES256":
		r, s, _ := ecdsa.Sign(rand.Reader, p.ecKey, digest[:])
		signature = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	}
	return input + "." + b64(signature)
}

// signIn runs start and callback against the provider and returns the
// callback's answer.
func signIn(t *testing.T, p *fakeProvider, allowSubjects ...string) result {
	t.Helper()
	config, err := oidcConfigFromValues(ptr(p.server.URL), ptr("motehold"), ptr("client-secret"), ptr("http://127.0.0.1:8787/auth/oidc/callback"))
	if err != nil {
		t.Fatal(err)
	}
	config.withAllowlist(allowSubjects, nil)
	a := testApp(t, false)
	a.auth.oidc = config
	start := call(a, "GET", "/auth/oidc/start", "", "")
	if start.status != http.StatusSeeOther {
		t.Fatalf("start: %d %s", start.status, start.body)
	}
	location, _ := url.Parse(start.header.Get("Location"))
	query := location.Query()
	if location.Path != "/authorize" || query.Get("code_challenge_method") != "S256" || query.Get("scope") != "openid profile email" ||
		query.Get("response_type") != "code" || query.Get("redirect_uri") != "http://127.0.0.1:8787/auth/oidc/callback" {
		t.Fatalf("authorize URL: %s", location)
	}
	p.nonce = query.Get("nonce")
	var flow string
	for _, value := range start.header.Values("Set-Cookie") {
		if strings.HasPrefix(value, "motehold_oidc_flow=") {
			flow = strings.SplitN(value, ";", 2)[0]
		}
	}
	callback := call(a, "GET", "/auth/oidc/callback?code=the-code&state="+url.QueryEscape(query.Get("state")), "", "", "Cookie", flow)
	if p.lastForm != nil {
		digest := sha256.Sum256([]byte(p.lastForm.Get("code_verifier")))
		if b64(digest[:]) != query.Get("code_challenge") || p.lastForm.Get("code") != "the-code" {
			t.Fatal("PKCE verifier does not match the challenge")
		}
	}
	return callback
}

func TestAWholeSignInWithEachAlgorithm(t *testing.T) {
	for _, alg := range []string{"EdDSA", "RS256", "ES256"} {
		p := newFakeProvider(t, alg)
		r := signIn(t, p)
		if r.status != http.StatusSeeOther || r.header.Get("Location") != "/" {
			t.Fatalf("%s: %d %s", alg, r.status, r.body)
		}
		sessionCookieFrom(t, r)
	}
}

func TestClientSecretPostPutsCredentialsInTheTokenRequestBody(t *testing.T) {
	p := newFakeProvider(t, "EdDSA")
	signIn(t, p)
	if p.lastAuth != "" || p.lastForm.Get("client_id") != "motehold" || p.lastForm.Get("client_secret") != "client-secret" {
		t.Fatal(p.lastAuth, p.lastForm)
	}
	p.authMethod = []string{"client_secret_basic"}
	signIn(t, p)
	if p.lastForm.Get("client_secret") != "" || !strings.HasPrefix(p.lastAuth, "Basic ") {
		t.Fatal(p.lastAuth, p.lastForm)
	}
}

func TestSignInRefusals(t *testing.T) {
	cases := []struct {
		name   string
		change func(p *fakeProvider)
		status int
	}{
		{"wrong nonce", func(p *fakeProvider) {
			base := p.claims
			p.claims = func(string) map[string]any { c := base(""); c["nonce"] = "other"; return c }
		}, 401},
		{"another audience too", func(p *fakeProvider) {
			base := p.claims
			p.claims = func(n string) map[string]any { c := base(n); c["aud"] = []string{"motehold", "other"}; return c }
		}, 401},
		{"wrong issuer", func(p *fakeProvider) {
			base := p.claims
			p.claims = func(n string) map[string]any { c := base(n); c["iss"] = "https://evil.example"; return c }
		}, 401},
		{"expired", func(p *fakeProvider) {
			base := p.claims
			p.claims = func(n string) map[string]any { c := base(n); c["exp"] = time.Now().Add(-time.Minute).Unix(); return c }
		}, 401},
		{"bad signature", func(p *fakeProvider) {
			p.tamper = func(token string) string { return token[:len(token)-4] + "AAAA" }
		}, 401},
		{"unknown key id", func(p *fakeProvider) { p.header = map[string]any{"kid": "nope"} }, 401},
		{"unexpected type", func(p *fakeProvider) { p.header = map[string]any{"typ": "at+jwt"} }, 401},
		{"no ID token", func(p *fakeProvider) {
			p.answerBody = func(string) string { return answerWithout("id_token") }
		}, 502},
		{"malformed ID token", func(p *fakeProvider) {
			p.answerBody = func(string) string { return answerWithout("") + "x.y\"}" }
		}, 502},
		{"no subject claim", func(p *fakeProvider) {
			base := p.claims
			p.claims = func(n string) map[string]any { c := base(n); delete(c, "sub"); return c }
		}, 502},
	}
	for _, c := range cases {
		p := newFakeProvider(t, "EdDSA")
		c.change(p)
		if r := signIn(t, p); r.status != c.status {
			t.Errorf("%s: %d, want %d", c.name, r.status, c.status)
		}
	}
	// An algorithm the provider does not list is refused.
	p := newFakeProvider(t, "EdDSA")
	p.alg = "RS256"
	p.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"issuer": p.server.URL, "authorization_endpoint": p.server.URL + "/authorize",
				"token_endpoint": p.server.URL + "/token", "jwks_uri": p.server.URL + "/jwks",
				"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
				"id_token_signing_alg_values_supported": []string{"EdDSA"},
			})
			return
		}
		p.serve(w, r)
	})
	if r := signIn(t, p); r.status != http.StatusUnauthorized {
		t.Errorf("unlisted algorithm: %d", r.status)
	}
	// The allowlist refuses other subjects.
	if r := signIn(t, newFakeProvider(t, "EdDSA"), "someone-else"); r.status != http.StatusForbidden {
		t.Errorf("allowlist: %d", r.status)
	}
}

func TestDiscoveryRefusesRedirectsAndWrongIssuer(t *testing.T) {
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
	}))
	defer redirecting.Close()
	if _, err := discoverClient(&oidcConfig{issuer: redirecting.URL}); err == nil {
		t.Fatal("redirect followed")
	}
	p := newFakeProvider(t, "EdDSA")
	if _, err := discoverClient(&oidcConfig{issuer: p.server.URL + "/"}); err == nil {
		t.Fatal("issuer mismatch accepted")
	}
}

func TestAuthorizeURLEncodesAsTheCrateDid(t *testing.T) {
	c := &oidcClient{config: &oidcConfig{clientID: "a b~*", redirectURL: "https://app.example/auth/oidc/callback"},
		metadata: providerMetadata{AuthorizationEndpoint: "https://idp.example/authorize?tenant=x"}}
	got := c.authorizeURL("S", "C", "N")
	want := "https://idp.example/authorize?tenant=x&response_type=code&client_id=a+b%7E*&state=S&code_challenge=C&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fapp.example%2Fauth%2Foidc%2Fcallback&scope=openid+profile+email&nonce=N"
	if got != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
}
