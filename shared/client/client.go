package client

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// Config holds the configuration for an OAuth client with mTLS support
type Config struct {
	ClientID     string
	WellKnownURL string
	MTLSClient   *http.Client
	JWTSigner    jose.Signer
}

// OAuthClient provides OAuth functionality with mTLS support
type OAuthClient struct {
	cfg Config
}

// GetJWTSigner returns the JWT signer from the config
func (c *OAuthClient) GetJWTSigner() jose.Signer {
	return c.cfg.JWTSigner
}

// New creates a new OAuth client
func New(cfg Config) *OAuthClient {
	return &OAuthClient{cfg: cfg}
}

// BuildClientAssertion creates a JWT client assertion for OAuth authentication
func (c *OAuthClient) BuildClientAssertion() (string, error) {
	if c.cfg.JWTSigner == nil {
		return "", fmt.Errorf("jwt signer not configured")
	}
	wellKnown, err := url.Parse(c.cfg.WellKnownURL)
	if err != nil {
		return "", fmt.Errorf("invalid well-known URL: %w", err)
	}
	issuer := wellKnown.Scheme + "://" + wellKnown.Host
	now := time.Now().Unix()
	claims := map[string]any{
		"iss": c.cfg.ClientID,
		"sub": c.cfg.ClientID,
		"jti": randAlphaNum(20),
		"iat": now,
		"exp": now + 60,
		"aud": issuer,
	}
	return jwt.Signed(c.cfg.JWTSigner).Claims(claims).Serialize()
}

// GetJSON makes an authenticated GET request and returns the JSON response
func (c *OAuthClient) GetJSON(ctx context.Context, uri, accessToken string) (map[string]any, int, error) {
	if accessToken == "" {
		return nil, 0, fmt.Errorf("access token required")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.cfg.MTLSClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("read response body: %w", err)
	}

	var out map[string]any
	if len(body) > 0 {
		if err := json.Unmarshal(body, &out); err != nil {
			slog.ErrorContext(ctx, "api call bad json", "uri", uri, "status_code", resp.StatusCode, "error", err)
			return nil, 0, fmt.Errorf("decode json: %w (status=%s, body=%s)", err, resp.Status, string(body))
		}
	} else {
		out = map[string]any{}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		slog.WarnContext(ctx, "api call non_2xx", "uri", uri, "status_code", resp.StatusCode)
	} else {
		slog.InfoContext(ctx, "api call success", "uri", uri, "status_code", resp.StatusCode)
	}

	return out, resp.StatusCode, nil
}

// PostForm makes an authenticated POST request with form data
func (c *OAuthClient) PostForm(ctx context.Context, uri string, form url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.cfg.MTLSClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}

	return resp, nil
}

// PostFormWithClientAssertion makes a POST request with form data and client assertion
func (c *OAuthClient) PostFormWithClientAssertion(ctx context.Context, uri string, form url.Values) (*http.Response, error) {
	clientAssertion, err := c.BuildClientAssertion()
	if err != nil {
		return nil, fmt.Errorf("build client assertion: %w", err)
	}

	form.Set("client_assertion", clientAssertion)
	form.Set("client_assertion_type", clientAssertionType)

	return c.PostForm(ctx, uri, form)
}

// randAlphaNum generates a random alphanumeric string of length n
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
