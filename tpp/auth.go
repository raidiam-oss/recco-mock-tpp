package tpp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/raidiam/recco-mock-tpp/shared/model"
)

// BuildAuthParams creates OAuth authorization parameters and returns a session ID
func (t *TPP) BuildAuthParams(ctx context.Context, scopes []string) (sessionID string, out model.BuildAuthOutput, err error) {
	responseType := "code"
	responseMode := "query"
	scope := strings.Join(scopes, " ")
	verifier, challenge := pkcePair()
	state := uuid.NewString()
	nonce := randAlphaNum(10)

	sessionID = uuid.NewString()
	t.sessMu.Lock()
	t.sessions[sessionID] = &model.RuntimeSession{
		State:        state,
		CodeVerifier: verifier,
		Scope:        scope,
		Nonce:        nonce,
		ResponseType: responseType,
		ResponseMode: responseMode,
	}
	t.sessMu.Unlock()

	out = model.BuildAuthOutput{
		ClientID:      t.cfg.ClientID,
		RedirectURI:   t.cfg.RedirectURI,
		Scope:         scope,
		CodeChallenge: challenge,
		State:         state,
		Nonce:         nonce,
		ResponseType:  responseType,
	}

	slog.InfoContext(ctx, "auth params built",
		"client_id", t.cfg.ClientID,
		"redirect_uri", t.cfg.RedirectURI,
		"scopes", scope,
		"response_type", responseType,
		"response_mode", responseMode,
	)

	return sessionID, out, nil
}

// FinalizeAuthURL builds the final authorization URL using PAR (Pushed Authorization Request)
func (t *TPP) FinalizeAuthURL(ctx context.Context, sessionID string) (string, error) {
	sess := t.getSession(sessionID)
	if sess == nil {
		return "", fmt.Errorf("session not found")
	}

	if t.cfg.OAuthClient == nil {
		return "", fmt.Errorf("OAuth client not configured")
	}

	cfg := t.oidc

	codeVerifier := sha256.Sum256([]byte(sess.CodeVerifier))
	challenge := base64.RawURLEncoding.EncodeToString(codeVerifier[:])

	now := time.Now().Unix()
	exp := now + 5*60

	// build request
	requestObj := map[string]any{
		"response_type":         sess.ResponseType,
		"response_mode":         sess.ResponseMode,
		"client_id":             t.cfg.ClientID,
		"redirect_uri":          t.cfg.RedirectURI,
		"scope":                 sess.Scope,
		"code_challenge_method": "S256",
		"code_challenge":        challenge,
		"state":                 sess.State,
		"nonce":                 sess.Nonce,
		"prompt":                "consent",
		"nbf":                   now,
		"exp":                   exp,
		"aud":                   cfg.Issuer,
		"iss":                   t.cfg.ClientID,
	}

	jws, err := jwt.Signed(t.cfg.OAuthClient.GetJWTSigner()).Claims(requestObj).Serialize()
	if err != nil {
		return "", fmt.Errorf("sign request object: %w", err)
	}

	// build and send PAR request
	parForm := url.Values{}
	parForm.Set("request", jws)
	parForm.Set("prompt", "consent")

	parResp, err := t.cfg.OAuthClient.PostFormWithClientAssertion(ctx, cfg.MTLS.PushedAuthEndpoint, parForm)
	if err != nil {
		return "", fmt.Errorf("PAR request failed: %w", err)
	}
	defer parResp.Body.Close()

	var parOut struct {
		ExpiresIn  int    `json:"expires_in"`
		RequestURI string `json:"request_uri"`
	}
	if err := json.NewDecoder(parResp.Body).Decode(&parOut); err != nil {
		return "", fmt.Errorf("decode PAR response: %w", err)
	}
	if parResp.StatusCode < 200 || parResp.StatusCode >= 300 {
		return "", fmt.Errorf("PAR endpoint error: %s", parResp.Status)
	}
	if parOut.RequestURI == "" {
		return "", fmt.Errorf("PAR response missing request_uri")
	}

	// build auth url
	u, err := url.Parse(cfg.AuthEndpoint)
	if err != nil {
		return "", fmt.Errorf("bad auth endpoint: %w", err)
	}
	q := url.Values{}
	q.Set("response_type", sess.ResponseType)
	q.Set("response_mode", sess.ResponseMode)
	q.Set("client_id", t.cfg.ClientID)
	q.Set("redirect_uri", t.cfg.RedirectURI)
	q.Set("scope", sess.Scope)
	q.Set("request_uri", parOut.RequestURI)
	q.Set("prompt", "consent")
	raw := q.Encode()
	raw = strings.ReplaceAll(raw, "+", "%20")
	u.RawQuery = raw

	authURL := u.String()
	slog.InfoContext(ctx, "auth url built (via PAR)", "url", authURL)
	return authURL, nil
}

// ExchangeToken exchanges an authorization code for tokens
func (t *TPP) ExchangeToken(ctx context.Context, sessionID, code, state string) (map[string]any, error) {
	sess := t.getSession(sessionID)
	if sess == nil {
		return nil, fmt.Errorf("session not found")
	}
	if sess.State != state {
		return nil, fmt.Errorf("invalid state")
	}

	oidc := t.oidc

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", t.cfg.RedirectURI)
	form.Set("code_verifier", sess.CodeVerifier)

	resp, err := t.cfg.OAuthClient.PostFormWithClientAssertion(ctx, oidc.MTLS.TokenEndpoint, form)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	var tokens map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return nil, fmt.Errorf("token decode failed: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return tokens, fmt.Errorf("token endpoint error: %s", resp.Status)
	}

	// extract access token from response
	accessToken, ok := tokens["access_token"].(string)
	if !ok || accessToken == "" {
		return nil, fmt.Errorf("access token not found")
	}

	// store access token in session
	t.sessMu.Lock()
	sess.AccessToken = accessToken
	t.sessMu.Unlock()

	// introspect the access token over mTLS
	if oidc.MTLS.IntrospectionEndpoint != "" {
		introspect := url.Values{}
		introspect.Set("token", accessToken)

		iresp, err := t.cfg.OAuthClient.PostFormWithClientAssertion(ctx, oidc.MTLS.IntrospectionEndpoint, introspect)
		if err != nil {
			tokens["introspection_error"] = fmt.Sprintf("do request: %v", err)
			return tokens, nil
		}
		defer iresp.Body.Close()

		var ires map[string]any
		if err := json.NewDecoder(iresp.Body).Decode(&ires); err != nil {
			tokens["introspection_error"] = fmt.Sprintf("decode response: %v", err)
			return tokens, nil
		}

		tokens["introspection"] = ires
		slog.InfoContext(ctx, "token introspection ok")
	}

	slog.InfoContext(ctx, "FAPI 2.0 compliant token exchange completed")
	return tokens, nil
}

func (t *TPP) getSession(id string) *model.RuntimeSession {
	t.sessMu.Lock()
	defer t.sessMu.Unlock()
	return t.sessions[id]
}

// PKCE helper functions

func pkcePair() (verifier, challenge string) {
	b := make([]byte, 50)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate random bytes for PKCE: %v", err))
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return
}

func randAlphaNum(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	rb := make([]byte, n)
	if _, err := rand.Read(rb); err != nil {
		panic(fmt.Sprintf("failed to generate random bytes for alphanumeric string: %v", err))
	}
	for i := range b {
		b[i] = letters[int(rb[i])%len(letters)]
	}
	return string(b)
}
