package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
)

// Optional OpenID Connect sign-in: Authorization Code with S256 PKCE,
// state and nonce, written with net/http and the standard library's crypto
// in place of the openidconnect crate. ID tokens signed with EdDSA
// (Ed25519, what lmidentityd uses), RS256, ES256 or HS256 are checked; the
// issuer, audience, expiry and nonce are checked as the crate did. Provider
// tokens are dropped after the callback; only an opaque app session is kept.

const (
	pendingFlowMinutes = 10
	flowCookie         = "motehold_oidc_flow"
	oidcBodyLimit      = 1 << 20
)

type oidcConfig struct {
	issuer, clientID, clientSecret, redirectURL string
	allowedSubjects                             []string // empty: any subject
	allowedEmails                               []string // lower-cased; empty: any email
}

func oidcConfigFromEnv() (*oidcConfig, error) {
	config, err := oidcConfigFromValues(envValue("MOTEHOLD_OIDC_ISSUER"), envValue("MOTEHOLD_OIDC_CLIENT_ID"),
		envValue("MOTEHOLD_OIDC_CLIENT_SECRET"), envValue("MOTEHOLD_OIDC_REDIRECT_URL"))
	if err != nil || config == nil {
		return nil, err
	}
	return config.withAllowlist(envList("MOTEHOLD_OIDC_ALLOWED_SUBJECTS"), envList("MOTEHOLD_OIDC_ALLOWED_EMAILS")), nil
}

func oidcConfigFromValues(issuer, clientID, clientSecret, redirectURL *string) (*oidcConfig, error) {
	set := 0
	for _, value := range []*string{issuer, clientID, clientSecret, redirectURL} {
		if value != nil {
			set++
		}
	}
	if set == 0 {
		return nil, nil
	}
	if set != 4 {
		return nil, errors.New("MOTEHOLD_OIDC_ISSUER, MOTEHOLD_OIDC_CLIENT_ID, MOTEHOLD_OIDC_CLIENT_SECRET, and MOTEHOLD_OIDC_REDIRECT_URL must be set together")
	}
	if err := validateOIDCURL("MOTEHOLD_OIDC_ISSUER", *issuer, false); err != nil {
		return nil, err
	}
	if err := validateOIDCURL("MOTEHOLD_OIDC_REDIRECT_URL", *redirectURL, true); err != nil {
		return nil, err
	}
	return &oidcConfig{issuer: *issuer, clientID: *clientID, clientSecret: *clientSecret, redirectURL: *redirectURL}, nil
}

func (c *oidcConfig) withAllowlist(subjects, emails []string) *oidcConfig {
	c.allowedSubjects = subjects
	c.allowedEmails = nil
	for _, email := range emails {
		c.allowedEmails = append(c.allowedEmails, strings.ToLower(email))
	}
	return c
}

// restrictsIdentities is true when an allowlist limits who may log in.
func (c *oidcConfig) restrictsIdentities() bool {
	return len(c.allowedSubjects) > 0 || len(c.allowedEmails) > 0
}

// permits says whether a verified identity may log in: with no allowlist
// everyone the issuer vouches for; otherwise a listed subject or email.
func (c *oidcConfig) permits(subject string, email *string) bool {
	if !c.restrictsIdentities() {
		return true
	}
	return slices.Contains(c.allowedSubjects, subject) ||
		(email != nil && slices.Contains(c.allowedEmails, strings.ToLower(*email)))
}

func (c *oidcConfig) usesSecureCookie() bool {
	u, err := url.Parse(c.redirectURL)
	return err == nil && strings.EqualFold(u.Scheme, "https")
}

// parseAbsoluteURL accepts what the url crate parses as an absolute URL.
func parseAbsoluteURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return nil, errors.New("not an absolute URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme == "http" || scheme == "https") && u.Host == "" {
		return nil, errors.New("not an absolute URL")
	}
	return u, nil
}

func validateOIDCURL(name, raw string, callback bool) error {
	u, err := parseAbsoluteURL(raw)
	if err != nil {
		return fmt.Errorf("%s must be an absolute URL", name)
	}
	if u.User != nil || strings.Contains(raw, "#") {
		return fmt.Errorf("%s contains forbidden URL parts", name)
	}
	if !secureOrLoopback(u) {
		return fmt.Errorf("%s must use HTTPS; HTTP is allowed only for loopback dogfood URLs", name)
	}
	if strings.Contains(raw, "?") {
		return fmt.Errorf("%s must not contain a query", name)
	}
	if callback && u.EscapedPath() != "/auth/oidc/callback" {
		return fmt.Errorf("%s must use the exact /auth/oidc/callback path", name)
	}
	return nil
}

// secureOrLoopback allows HTTPS, and HTTP only to localhost or an IPv4
// loopback address (the url crate's host_str() keeps IPv6 brackets, which
// never parsed as an address, so [::1] was refused).
func secureOrLoopback(u *url.URL) bool {
	switch strings.ToLower(u.Scheme) {
	case "https":
		return true
	case "http":
		host := u.Hostname()
		if strings.HasPrefix(u.Host, "[") {
			return false
		}
		if strings.EqualFold(host, "localhost") {
			return true
		}
		addr, err := netip.ParseAddr(host)
		return err == nil && addr.IsLoopback()
	}
	return false
}

func validateServiceEndpoint(name, raw string) error {
	u, err := parseAbsoluteURL(raw)
	if err != nil {
		return fmt.Errorf("%s is not a URL", name)
	}
	if u.User != nil || strings.Contains(raw, "#") {
		return fmt.Errorf("%s contains forbidden URL parts", name)
	}
	if !secureOrLoopback(u) {
		return fmt.Errorf("%s must use HTTPS; HTTP is allowed only for loopback dogfood URLs", name)
	}
	return nil
}

type providerMetadata struct {
	Issuer                   string    `json:"issuer"`
	AuthorizationEndpoint    string    `json:"authorization_endpoint"`
	TokenEndpoint            *string   `json:"token_endpoint"`
	UserinfoEndpoint         *string   `json:"userinfo_endpoint"`
	JWKSURI                  string    `json:"jwks_uri"`
	ResponseTypesSupported   *[]string `json:"response_types_supported"`
	SubjectTypesSupported    *[]string `json:"subject_types_supported"`
	IDTokenSigningAlgs       *[]string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethods *[]string `json:"token_endpoint_auth_methods_supported"`
}

type jsonWebKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// oidcClient is what discovery found: endpoints, keys and how to send the
// client secret.
type oidcClient struct {
	config     *oidcConfig
	metadata   providerMetadata
	keys       []jsonWebKey
	secretPost bool
	http       *http.Client
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		// Discovery redirects are refused, as are all others.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			TLSHandshakeTimeout: 5 * time.Second,
		},
	}
}

// getJSON fetches a document that must answer 200 with a JSON content type
// (or one of the extra types given).
func getJSON(client *http.Client, rawURL string, out any, extraTypes ...string) error {
	request, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "motehold")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, oidcBodyLimit+1))
	if err != nil {
		return err
	}
	if len(body) > oidcBodyLimit {
		return fmt.Errorf("%s answered more than %d bytes", rawURL, oidcBodyLimit)
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP status code %d at %s", response.StatusCode, rawURL)
	}
	if values := response.Header.Values("Content-Type"); len(values) > 0 {
		if !slices.Contains(append([]string{"application/json"}, extraTypes...), contentEssence(values[0])) {
			return fmt.Errorf("unexpected response Content-Type %q", values[0])
		}
	}
	return json.Unmarshal(body, out)
}

func contentEssence(value string) string {
	essence, _, _ := strings.Cut(value, ";")
	return strings.ToLower(essence)
}

func discoverClient(config *oidcConfig) (*oidcClient, error) {
	client := newHTTPClient()
	discoveryURL := config.issuer
	if !strings.HasSuffix(discoveryURL, "/") {
		discoveryURL += "/"
	}
	discoveryURL += ".well-known/openid-configuration"
	if err := validateServiceEndpoint("OIDC discovery request", discoveryURL); err != nil {
		return nil, err
	}
	var metadata providerMetadata
	if err := getJSON(client, discoveryURL, &metadata); err != nil {
		return nil, err
	}
	if metadata.AuthorizationEndpoint == "" || metadata.JWKSURI == "" || metadata.ResponseTypesSupported == nil ||
		metadata.SubjectTypesSupported == nil || metadata.IDTokenSigningAlgs == nil {
		return nil, errors.New("OIDC provider metadata lacks a required field")
	}
	if metadata.Issuer != config.issuer {
		return nil, fmt.Errorf("unexpected issuer URI `%s` (expected `%s`)", metadata.Issuer, config.issuer)
	}
	if err := validateServiceEndpoint("OIDC discovery request", metadata.JWKSURI); err != nil {
		return nil, err
	}
	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := getJSON(client, metadata.JWKSURI, &jwks, "application/jwk-set+json"); err != nil {
		return nil, err
	}
	var keys []jsonWebKey
	for _, raw := range jwks.Keys {
		var key jsonWebKey
		if json.Unmarshal(raw, &key) == nil {
			keys = append(keys, key)
		}
	}
	if err := validateServiceEndpoint("OIDC authorization endpoint", metadata.AuthorizationEndpoint); err != nil {
		return nil, err
	}
	if metadata.TokenEndpoint == nil {
		return nil, errors.New("OIDC provider has no token endpoint")
	}
	if err := validateServiceEndpoint("OIDC token endpoint", *metadata.TokenEndpoint); err != nil {
		return nil, err
	}
	if metadata.UserinfoEndpoint != nil {
		if err := validateServiceEndpoint("OIDC userinfo endpoint", *metadata.UserinfoEndpoint); err != nil {
			return nil, err
		}
	}
	if err := validateServiceEndpoint("OIDC JWKS endpoint", metadata.JWKSURI); err != nil {
		return nil, err
	}
	secretPost, err := selectTokenAuthMethod(metadata.TokenEndpointAuthMethods)
	if err != nil {
		return nil, err
	}
	return &oidcClient{config: config, metadata: metadata, keys: keys, secretPost: secretPost, http: client}, nil
}

// selectTokenAuthMethod prefers client_secret_post, supports
// client_secret_basic, and takes basic when the provider says nothing.
func selectTokenAuthMethod(advertised *[]string) (bool, error) {
	if advertised == nil {
		return false, nil
	}
	if slices.Contains(*advertised, "client_secret_post") {
		return true, nil
	}
	if slices.Contains(*advertised, "client_secret_basic") {
		return false, nil
	}
	return false, errors.New("OIDC provider supports neither client_secret_post nor client_secret_basic")
}

// formEncode is form_urlencoded's byte_serialize: letters, digits and
// *-._ stay, a space is '+', every other byte is %XX.
func formEncode(value string) string {
	var b strings.Builder
	for _, c := range []byte(value) {
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '*', c == '-', c == '.', c == '_':
			b.WriteByte(c)
		case c == ' ':
			b.WriteByte('+')
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func encodePairs(pairs [][2]string) string {
	parts := make([]string, len(pairs))
	for i, pair := range pairs {
		parts[i] = formEncode(pair[0]) + "=" + formEncode(pair[1])
	}
	return strings.Join(parts, "&")
}

func (c *oidcClient) authorizeURL(state, challenge, nonce string) string {
	query := encodePairs([][2]string{
		{"response_type", "code"}, {"client_id", c.config.clientID}, {"state", state},
		{"code_challenge", challenge}, {"code_challenge_method", "S256"},
		{"redirect_uri", c.config.redirectURL}, {"scope", "openid profile email"}, {"nonce", nonce},
	})
	endpoint := c.metadata.AuthorizationEndpoint
	if strings.Contains(endpoint, "?") {
		return endpoint + "&" + query
	}
	return endpoint + "?" + query
}

type tokenResponse struct {
	AccessToken *string `json:"access_token"`
	TokenType   *string `json:"token_type"`
	IDToken     *string `json:"id_token"`
}

// exchangeCode trades the code for tokens; a malformed answer or ID token
// is an error here, as it was a request error in the crate.
func (c *oidcClient) exchangeCode(code, verifier string) (*idToken, bool, error) {
	pairs := [][2]string{{"grant_type", "authorization_code"}, {"code", code}, {"code_verifier", verifier}}
	if c.secretPost {
		pairs = append(pairs, [2]string{"client_id", c.config.clientID}, [2]string{"client_secret", c.config.clientSecret})
	}
	pairs = append(pairs, [2]string{"redirect_uri", c.config.redirectURL})
	request, err := http.NewRequest(http.MethodPost, *c.metadata.TokenEndpoint, strings.NewReader(encodePairs(pairs)))
	if err != nil {
		return nil, false, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("User-Agent", "motehold")
	if !c.secretPost {
		credential := formEncode(c.config.clientID) + ":" + formEncode(c.config.clientSecret)
		request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(credential)))
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, false, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, oidcBodyLimit+1))
	if err != nil {
		return nil, false, err
	}
	if len(body) > oidcBodyLimit || response.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("token endpoint answered %d", response.StatusCode)
	}
	if values := response.Header.Values("Content-Type"); len(values) > 0 && !strings.HasPrefix(strings.ToLower(values[0]), "application/json") {
		return nil, false, fmt.Errorf("unexpected token response Content-Type %q", values[0])
	}
	var tokens tokenResponse
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, false, err
	}
	if tokens.AccessToken == nil || tokens.TokenType == nil {
		return nil, false, errors.New("token response lacks access_token or token_type")
	}
	if tokens.IDToken == nil {
		return nil, false, nil
	}
	token, err := parseIDToken(*tokens.IDToken)
	if err != nil {
		return nil, false, err
	}
	return token, true, nil
}

type audiences []string

func (a *audiences) UnmarshalJSON(raw []byte) error {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		*a = audiences{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

type idToken struct {
	header struct {
		Alg  string           `json:"alg"`
		Kid  *string          `json:"kid"`
		Typ  *string          `json:"typ"`
		Cty  *string          `json:"cty"`
		Crit *json.RawMessage `json:"crit"`
	}
	claims struct {
		Iss   *string      `json:"iss"`
		Aud   *audiences   `json:"aud"`
		Exp   *json.Number `json:"exp"`
		Iat   *json.Number `json:"iat"`
		Sub   *string      `json:"sub"`
		Nonce *string      `json:"nonce"`
		Email *string      `json:"email"`
	}
	signingInput []byte
	signature    []byte
}

func parseIDToken(raw string) (*idToken, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("ID token is not a signed JWT")
	}
	headerJSON, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	claimsJSON, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	signature, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, errors.New("ID token is not base64url")
	}
	token := &idToken{signingInput: []byte(parts[0] + "." + parts[1]), signature: signature}
	if err := json.Unmarshal(headerJSON, &token.header); err != nil || token.header.Alg == "" {
		return nil, errors.New("ID token header is unreadable")
	}
	decoder := json.NewDecoder(bytes.NewReader(claimsJSON))
	decoder.UseNumber()
	if err := decoder.Decode(&token.claims); err != nil {
		return nil, errors.New("ID token claims are unreadable")
	}
	c := token.claims
	if c.Iss == nil || c.Aud == nil || c.Exp == nil || c.Iat == nil || c.Sub == nil {
		return nil, errors.New("ID token lacks a required claim")
	}
	if _, err := c.Exp.Float64(); err != nil {
		return nil, errors.New("ID token exp is not a number")
	}
	return token, nil
}

// verify is the crate's ID token check: header, issuer, audience, allowed
// algorithm, signature, expiry and nonce.
func (c *oidcClient) verify(token *idToken, nonce string, now time.Time) error {
	h := token.header
	if h.Typ != nil {
		typ := strings.ToLower(*h.Typ)
		if !strings.Contains(typ, "/") {
			typ = "application/" + typ
		}
		if typ != "application/jwt" && typ != "application/jose" {
			return errors.New("unexpected JWT type")
		}
	}
	if h.Cty != nil || h.Crit != nil {
		return errors.New("unsupported JWT header field")
	}
	claims := token.claims
	if *claims.Iss != c.config.issuer {
		return errors.New("invalid issuer")
	}
	aud := *claims.Aud
	if !slices.Contains(aud, c.config.clientID) {
		return errors.New("invalid audience")
	}
	for _, other := range aud {
		if other != c.config.clientID {
			return fmt.Errorf("`%s` is not a trusted audience", other)
		}
	}
	if !slices.Contains(*c.metadata.IDTokenSigningAlgs, h.Alg) {
		return fmt.Errorf("algorithm `%s` is not allowed", h.Alg)
	}
	if err := c.checkSignature(token); err != nil {
		return err
	}
	exp, _ := claims.Exp.Float64()
	if float64(now.UnixNano())/1e9 >= exp {
		return errors.New("ID token expired")
	}
	if claims.Nonce == nil {
		return errors.New("missing nonce claim")
	}
	got, want := sha256.Sum256([]byte(*claims.Nonce)), sha256.Sum256([]byte(nonce))
	if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
		return errors.New("nonce mismatch")
	}
	return nil
}

var keyTypes = map[string]string{"EdDSA": "OKP", "RS256": "RSA", "ES256": "EC"}

func (c *oidcClient) checkSignature(token *idToken) error {
	alg := token.header.Alg
	if alg == "HS256" {
		mac := hmac.New(sha256.New, []byte(c.config.clientSecret))
		mac.Write(token.signingInput)
		if !hmac.Equal(mac.Sum(nil), token.signature) {
			return errors.New("invalid signature")
		}
		return nil
	}
	kty, supported := keyTypes[alg]
	if !supported {
		return fmt.Errorf("unsupported signing algorithm `%s`", alg)
	}
	var matches []jsonWebKey
	for _, key := range c.keys {
		if token.header.Kid != nil && *token.header.Kid != key.Kid {
			continue
		}
		if (key.Use != "" && key.Use != "sig") || key.Kty != kty || (key.Alg != "" && key.Alg != alg) {
			continue
		}
		matches = append(matches, key)
	}
	if len(matches) != 1 {
		return fmt.Errorf("%d eligible keys for the ID token", len(matches))
	}
	key := matches[0]
	switch alg {
	case "EdDSA":
		x, err := base64.RawURLEncoding.DecodeString(key.X)
		if err != nil || key.Crv != "Ed25519" || len(x) != ed25519.PublicKeySize {
			return errors.New("unusable Ed25519 key")
		}
		if !ed25519.Verify(ed25519.PublicKey(x), token.signingInput, token.signature) {
			return errors.New("invalid signature")
		}
	case "RS256":
		n, err1 := base64.RawURLEncoding.DecodeString(key.N)
		e, err2 := base64.RawURLEncoding.DecodeString(key.E)
		if err1 != nil || err2 != nil || len(e) == 0 || len(e) > 4 {
			return errors.New("unusable RSA key")
		}
		exponent := 0
		for _, b := range e {
			exponent = exponent<<8 | int(b)
		}
		public := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exponent}
		digest := sha256.Sum256(token.signingInput)
		if rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], token.signature) != nil {
			return errors.New("invalid signature")
		}
	case "ES256":
		x, err1 := base64.RawURLEncoding.DecodeString(key.X)
		y, err2 := base64.RawURLEncoding.DecodeString(key.Y)
		if err1 != nil || err2 != nil || key.Crv != "P-256" || len(x) != 32 || len(y) != 32 || len(token.signature) != 64 {
			return errors.New("unusable P-256 key or signature")
		}
		public, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return errors.New("unusable P-256 key")
		}
		digest := sha256.Sum256(token.signingInput)
		r := new(big.Int).SetBytes(token.signature[:32])
		s := new(big.Int).SetBytes(token.signature[32:])
		if !ecdsa.Verify(public, digest[:], r, s) {
			return errors.New("invalid signature")
		}
	}
	return nil
}

func (a *app) oidcStart(r *http.Request) *response {
	config := a.auth.oidc
	if config == nil {
		return redirect("/login")
	}
	client, err := discoverClient(config)
	if err != nil {
		logError("OIDC discovery", err)
		return a.authError(http.StatusServiceUnavailable, "Organization login is temporarily unavailable. Local break-glass login remains available.")
	}
	verifier := base64.RawURLEncoding.EncodeToString(randomBytes(32))
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	state := base64.RawURLEncoding.EncodeToString(randomBytes(16))
	nonce := base64.RawURLEncoding.EncodeToString(randomBytes(16))
	location := client.authorizeURL(state, challenge, nonce)
	flowToken := randomToken()
	if err := a.storePendingFlow(state, flowToken, nonce, verifier, time.Now().Unix()); err != nil {
		logError("OIDC start", err)
		return a.authError(http.StatusInternalServerError, "Organization login could not be started.")
	}
	if _, ok := visibleASCII(location); !ok {
		return a.authError(http.StatusBadGateway, "Organization login failed.")
	}
	res := empty(http.StatusSeeOther)
	res.header.Set("Location", location)
	return res.cookie(fmt.Sprintf("%s=%s; Max-Age=%d; Path=/auth/oidc/callback; HttpOnly; SameSite=Lax%s",
		flowCookie, flowToken, pendingFlowMinutes*60, a.auth.secureSuffix()))
}

func (a *app) oidcCallback(r *http.Request) *response {
	query := parseURLEncoded(r.URL.RawQuery)
	if err := duplicateField(r.URL.RawQuery, "code", "state", "error"); err != nil {
		return queryRejection(err)
	}
	code, hasCode, _ := query.optional("code")
	returnedState, hasState, _ := query.optional("state")
	_, hasError, _ := query.optional("error")
	failed := func(status int, message string) *response {
		return a.finishCallback(a.authError(status, message))
	}
	if hasError {
		return failed(http.StatusUnauthorized, "Organization login was not completed.")
	}
	if !hasCode || !hasState {
		return failed(http.StatusBadRequest, "Invalid organization login response.")
	}
	flowToken, ok := cookieValue(r, flowCookie)
	if !ok {
		return failed(http.StatusBadRequest, "Organization login failed browser-flow verification.")
	}
	pending, err := a.takePendingFlow(returnedState, flowToken, time.Now().Unix())
	if err != nil || pending == nil {
		return failed(http.StatusBadRequest, "Organization login expired or failed state verification.")
	}
	config := a.auth.oidc
	if config == nil {
		return failed(http.StatusBadRequest, "Organization login is not configured.")
	}
	client, err := discoverClient(config)
	if err != nil {
		logError("OIDC discovery", err)
		return failed(http.StatusServiceUnavailable, "Organization login is temporarily unavailable. Local break-glass login remains available.")
	}
	token, hasToken, err := client.exchangeCode(code, pending.PKCEVerifier)
	if err != nil {
		logError("OIDC token exchange", err)
		return failed(http.StatusBadGateway, "Organization login failed.")
	}
	if !hasToken {
		return failed(http.StatusBadGateway, "Organization login returned no identity.")
	}
	if err := client.verify(token, pending.Nonce, time.Now()); err != nil {
		logError("OIDC identity verification", err)
		return failed(http.StatusUnauthorized, "Organization identity verification failed.")
	}
	subject := *token.claims.Sub
	if !config.permits(subject, token.claims.Email) {
		fmt.Fprintf(os.Stderr, "OIDC login refused: subject %q matches neither MOTEHOLD_OIDC_ALLOWED_SUBJECTS nor MOTEHOLD_OIDC_ALLOWED_EMAILS\n", subject)
		return failed(http.StatusForbidden, "This organization identity is not allowed to use Motehold.")
	}
	// Provider tokens are dropped here. Only an opaque app-owned session is kept.
	cookie, err := a.createSessionCookie("oidc", time.Now().Unix())
	if err != nil {
		return a.finishCallback(a.authError(http.StatusInternalServerError, "Could not create a session."))
	}
	return a.finishCallback(redirect("/").cookie(cookie))
}

func (a *app) finishCallback(res *response) *response {
	return res.cookie(fmt.Sprintf("%s=; Max-Age=0; Path=/auth/oidc/callback; HttpOnly; SameSite=Lax%s", flowCookie, a.auth.secureSuffix()))
}

func (a *app) storePendingFlow(state, flowToken, nonce, verifier string, now int64) error {
	flow := pendingFlow{
		StateHash: a.keyedHash("oidc-state", state), FlowHash: a.keyedHash("oidc-flow", flowToken),
		Nonce: nonce, PKCEVerifier: verifier, ExpiresAt: now + pendingFlowMinutes*60,
	}
	return a.store.update(func(d *storeData) error {
		d.PendingFlows = slices.DeleteFunc(d.PendingFlows, func(f pendingFlow) bool { return f.ExpiresAt <= now })
		d.PendingFlows = append(d.PendingFlows, flow)
		return nil
	})
}

// takePendingFlow is one-time: the state's flow is removed whether or not
// the browser binding matches, and only an unexpired match is returned.
func (a *app) takePendingFlow(state, flowToken string, now int64) (*pendingFlow, error) {
	stateHash, flowHash := a.keyedHash("oidc-state", state), a.keyedHash("oidc-flow", flowToken)
	var found *pendingFlow
	err := a.store.update(func(d *storeData) error {
		for _, f := range d.PendingFlows {
			if f.StateHash == stateHash && f.FlowHash == flowHash {
				match := f
				found = &match
			}
		}
		d.PendingFlows = slices.DeleteFunc(d.PendingFlows, func(f pendingFlow) bool { return f.StateHash == stateHash })
		return nil
	})
	if err != nil {
		return nil, err
	}
	if found == nil || found.ExpiresAt <= now {
		return nil, nil
	}
	return found, nil
}

// duplicateField is serde's "duplicate field" for the first of the given
// fields that appears twice, in query order.
func duplicateField(raw string, fields ...string) error {
	seen := map[string]bool{}
	for _, piece := range strings.Split(raw, "&") {
		if piece == "" {
			continue
		}
		name, _, _ := strings.Cut(piece, "=")
		name = lossyUTF8(percentDecode(strings.ReplaceAll(name, "+", " ")))
		if !slices.Contains(fields, name) {
			continue
		}
		if seen[name] {
			return fmt.Errorf("duplicate field `%s`", name)
		}
		seen[name] = true
	}
	return nil
}

func visibleASCII(value string) (string, bool) {
	for _, c := range []byte(value) {
		if !(c == '\t' || (c >= 32 && c < 127)) {
			return "", false
		}
	}
	return value, true
}

func envValue(name string) *string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return nil
	}
	return &value
}

func envList(name string) []string {
	value := envValue(name)
	if value == nil {
		return nil
	}
	var items []string
	for _, item := range strings.Split(*value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}
	return items
}
