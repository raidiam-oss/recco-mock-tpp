package tpp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/raidiam/recco-mock-tpp/shared/cache"
	"github.com/raidiam/recco-mock-tpp/shared/client"
	"github.com/raidiam/recco-mock-tpp/shared/model"
	"github.com/raidiam/recco-mock-tpp/tpp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildAuthParams(t *testing.T) {
	tests := []struct {
		name           string
		scopes         []string
		wantErr        bool
		validateOutput func(t *testing.T, sessionID string, output model.BuildAuthOutput)
	}{
		{
			name:    "single_scope_openid",
			scopes:  []string{"openid"},
			wantErr: false,
			validateOutput: func(t *testing.T, sessionID string, output model.BuildAuthOutput) {
				assert.NotEmpty(t, sessionID)
				assert.Equal(t, "test-client", output.ClientID)
				assert.Equal(t, "https://app.example/callback", output.RedirectURI)
				assert.Equal(t, "openid", output.Scope)
				assert.Equal(t, "code id_token", output.ResponseType)
				assert.NotEmpty(t, output.State)
				assert.NotEmpty(t, output.Nonce)
				assert.NotEmpty(t, output.CodeChallenge)
			},
		},
		{
			name:    "multiple_scopes",
			scopes:  []string{"openid", "customer", "energy"},
			wantErr: false,
			validateOutput: func(t *testing.T, sessionID string, output model.BuildAuthOutput) {
				assert.NotEmpty(t, sessionID)
				assert.Equal(t, "openid customer energy", output.Scope)
				assert.Equal(t, "code id_token", output.ResponseType)
			},
		},
		{
			name:    "empty_scopes",
			scopes:  []string{},
			wantErr: false,
			validateOutput: func(t *testing.T, sessionID string, output model.BuildAuthOutput) {
				assert.NotEmpty(t, sessionID)
				assert.Equal(t, "", output.Scope)
			},
		},
		{
			name:    "nil_scopes",
			scopes:  nil,
			wantErr: false,
			validateOutput: func(t *testing.T, sessionID string, output model.BuildAuthOutput) {
				assert.NotEmpty(t, sessionID)
				assert.Equal(t, "", output.Scope)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tppInstance := createTestTPP(t)
			ctx := context.Background()

			sessionID, output, err := tppInstance.BuildAuthParams(ctx, tc.scopes)

			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				tc.validateOutput(t, sessionID, output)
			}
		})
	}
}

func TestFinalizeAuthURL(t *testing.T) {
	tests := []struct {
		name            string
		setupSession    func(t *testing.T, tppInstance *tpp.TPP) string
		mockPARServer   func(t *testing.T) *httptest.Server
		wantErr         bool
		wantErrContains string
		validateURL     func(t *testing.T, authURL string)
	}{
		{
			name: "successful_par_request",
			setupSession: func(t *testing.T, tppInstance *tpp.TPP) string {
				sessionID, _, err := tppInstance.BuildAuthParams(context.Background(), []string{"openid"})
				require.NoError(t, err)
				return sessionID
			},
			mockPARServer: func(t *testing.T) *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/par" {
						err := r.ParseForm()
						require.NoError(t, err)
						assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", r.Form.Get("client_assertion_type"))
						assert.NotEmpty(t, r.Form.Get("client_assertion"))
						assert.NotEmpty(t, r.Form.Get("request"))

						err = json.NewEncoder(w).Encode(map[string]any{
							"expires_in":  90,
							"request_uri": "urn:ietf:params:oauth:request_uri:TESTPAR",
						})
						require.NoError(t, err)
					}
				}))
			},
			wantErr: false,
			validateURL: func(t *testing.T, authURL string) {
				assert.Contains(t, authURL, "https://auth.example/authorize")
				assert.Contains(t, authURL, "request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3ATESTPAR")
				assert.Contains(t, authURL, "client_id=test-client")
			},
		},
		{
			name: "invalid_session_id",
			setupSession: func(t *testing.T, tppInstance *tpp.TPP) string {
				return "invalid-session-id"
			},
			mockPARServer: func(t *testing.T) *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			},
			wantErr:         true,
			wantErrContains: "session not found",
		},
		{
			name: "par_server_error",
			setupSession: func(t *testing.T, tppInstance *tpp.TPP) string {
				sessionID, _, err := tppInstance.BuildAuthParams(context.Background(), []string{"openid"})
				require.NoError(t, err)
				return sessionID
			},
			mockPARServer: func(t *testing.T) *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/par" {
						w.WriteHeader(http.StatusBadRequest)
						err := json.NewEncoder(w).Encode(map[string]any{"error": "invalid_request"})
						require.NoError(t, err)
					}
				}))
			},
			wantErr:         true,
			wantErrContains: "PAR endpoint error",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parServer := tc.mockPARServer(t)
			defer parServer.Close()

			tppInstance := createTestTPPWithPARServer(t, parServer)
			sessionID := tc.setupSession(t, tppInstance)
			ctx := context.Background()

			authURL, err := tppInstance.FinalizeAuthURL(ctx, sessionID)

			if tc.wantErr {
				require.Error(t, err)
				if tc.wantErrContains != "" {
					assert.Contains(t, err.Error(), tc.wantErrContains)
				}
			} else {
				require.NoError(t, err)
				tc.validateURL(t, authURL)
			}
		})
	}
}

func TestExchangeToken(t *testing.T) {
	tests := []struct {
		name            string
		setupSession    func(t *testing.T, tppInstance *tpp.TPP) (string, string) // returns sessionID, state
		code            string
		state           string
		mockTokenServer func(t *testing.T) *httptest.Server
		wantErr         bool
		wantErrContains string
		validateTokens  func(t *testing.T, tokens map[string]any)
	}{
		{
			name: "successful_token_exchange",
			setupSession: func(t *testing.T, tppInstance *tpp.TPP) (string, string) {
				sessionID, output, err := tppInstance.BuildAuthParams(context.Background(), []string{"openid"})
				require.NoError(t, err)
				return sessionID, output.State
			},
			code: "valid-code",
			mockTokenServer: func(t *testing.T) *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/token":
						err := r.ParseForm()
						require.NoError(t, err)
						assert.Equal(t, "authorization_code", r.Form.Get("grant_type"))
						assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", r.Form.Get("client_assertion_type"))
						assert.NotEmpty(t, r.Form.Get("client_assertion"))
						assert.NotEmpty(t, r.Form.Get("code_verifier"))

						err = json.NewEncoder(w).Encode(map[string]any{
							"access_token": "AT",
							"id_token":     "header.payload.sig",
							"token_type":   "Bearer",
							"expires_in":   3600,
						})
						require.NoError(t, err)
					case "/introspect":
						err := r.ParseForm()
						require.NoError(t, err)
						assert.NotEmpty(t, r.Form.Get("token"))
						err = json.NewEncoder(w).Encode(map[string]any{
							"active": true,
							"scope":  "openid customer energy",
						})
						require.NoError(t, err)
					}
				}))
			},
			wantErr: false,
			validateTokens: func(t *testing.T, tokens map[string]any) {
				assert.Equal(t, "AT", tokens["access_token"])
				assert.Equal(t, "header.payload.sig", tokens["id_token"])
				assert.Equal(t, "Bearer", tokens["token_type"])

				intro, ok := tokens["introspection"].(map[string]any)
				require.True(t, ok)
				assert.Equal(t, true, intro["active"])
			},
		},
		{
			name: "invalid_state",
			setupSession: func(t *testing.T, tppInstance *tpp.TPP) (string, string) {
				sessionID, output, err := tppInstance.BuildAuthParams(context.Background(), []string{"openid"})
				require.NoError(t, err)
				return sessionID, output.State
			},
			code:  "valid-code",
			state: "invalid-state",
			mockTokenServer: func(t *testing.T) *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			},
			wantErr:         true,
			wantErrContains: "invalid state",
		},
		{
			name: "token_endpoint_error",
			setupSession: func(t *testing.T, tppInstance *tpp.TPP) (string, string) {
				sessionID, output, err := tppInstance.BuildAuthParams(context.Background(), []string{"openid"})
				require.NoError(t, err)
				return sessionID, output.State
			},
			code: "bad-code",
			mockTokenServer: func(t *testing.T) *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/token" {
						w.WriteHeader(http.StatusBadRequest)
						err := json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"})
						require.NoError(t, err)
					}
				}))
			},
			wantErr:         true,
			wantErrContains: "token endpoint error",
			validateTokens: func(t *testing.T, tokens map[string]any) {
				assert.Equal(t, "invalid_grant", tokens["error"])
			},
		},
		{
			name: "session_not_found",
			setupSession: func(t *testing.T, tppInstance *tpp.TPP) (string, string) {
				return "invalid-session", "some-state"
			},
			code: "valid-code",
			mockTokenServer: func(t *testing.T) *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			},
			wantErr:         true,
			wantErrContains: "session not found",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tokenServer := tc.mockTokenServer(t)
			defer tokenServer.Close()

			tppInstance := createTestTPPWithTokenServer(t, tokenServer)
			sessionID, expectedState := tc.setupSession(t, tppInstance)

			state := tc.state
			if state == "" {
				state = expectedState
			}

			ctx := context.Background()
			tokens, err := tppInstance.ExchangeToken(ctx, sessionID, tc.code, state)

			if tc.wantErr {
				if tc.validateTokens != nil {
					tc.validateTokens(t, tokens)
				}
				if tc.wantErrContains != "" {
					require.Error(t, err)
					assert.Contains(t, err.Error(), tc.wantErrContains)
				}
			} else {
				require.NoError(t, err)
				tc.validateTokens(t, tokens)
			}
		})
	}
}

func TestPKCEHelpers(t *testing.T) {
	// Test pkcePair function through reflection or by testing BuildAuthParams
	// Since pkcePair is not exported, we test it indirectly
	t.Run("pkce_generates_different_values", func(t *testing.T) {
		tppInstance := createTestTPP(t)
		ctx := context.Background()

		_, output1, err1 := tppInstance.BuildAuthParams(ctx, []string{"openid"})
		require.NoError(t, err1)

		_, output2, err2 := tppInstance.BuildAuthParams(ctx, []string{"openid"})
		require.NoError(t, err2)

		// Code challenges should be different for different sessions
		assert.NotEqual(t, output1.CodeChallenge, output2.CodeChallenge)
		assert.NotEqual(t, output1.State, output2.State)
		assert.NotEqual(t, output1.Nonce, output2.Nonce)
	})

	t.Run("pkce_challenge_format", func(t *testing.T) {
		tppInstance := createTestTPP(t)
		ctx := context.Background()

		_, output, err := tppInstance.BuildAuthParams(ctx, []string{"openid"})
		require.NoError(t, err)

		// Code challenge should be base64 URL encoded (no padding)
		assert.NotContains(t, output.CodeChallenge, "=")
		assert.NotContains(t, output.CodeChallenge, "+")
		assert.NotContains(t, output.CodeChallenge, "/")
		assert.Greater(t, len(output.CodeChallenge), 40) // SHA256 hash should be reasonably long
	})
}

func TestRandAlphaNum(t *testing.T) {
	// Test randAlphaNum function indirectly through nonce generation
	t.Run("nonce_generation", func(t *testing.T) {
		tppInstance := createTestTPP(t)
		ctx := context.Background()

		_, output1, err1 := tppInstance.BuildAuthParams(ctx, []string{"openid"})
		require.NoError(t, err1)

		_, output2, err2 := tppInstance.BuildAuthParams(ctx, []string{"openid"})
		require.NoError(t, err2)

		// Nonces should be different
		assert.NotEqual(t, output1.Nonce, output2.Nonce)

		// Nonces should be alphanumeric
		assert.Regexp(t, `^[a-zA-Z0-9]+$`, output1.Nonce)
		assert.Regexp(t, `^[a-zA-Z0-9]+$`, output2.Nonce)

		// Nonces should have expected length (10 characters based on code)
		assert.Len(t, output1.Nonce, 10)
		assert.Len(t, output2.Nonce, 10)
	})
}

// Helper functions for creating test instances

func createTestTPP(t *testing.T) *tpp.TPP {
	return createSimpleTestTPP(t)
}

func createTestTPPWithPARServer(t *testing.T, parServer *httptest.Server) *tpp.TPP {
	t.Helper()

	// Create well-known server that points to our PAR server
	wellKnownServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 "https://auth.example",
			"authorization_endpoint": "https://auth.example/authorize",
			"mtls_endpoint_aliases": map[string]any{
				"pushed_authorization_request_endpoint": parServer.URL + "/par",
				"token_endpoint":                        "https://mtls.example/token",
				"introspection_endpoint":                "https://mtls.example/introspect",
			},
		})
		require.NoError(t, err)
	}))
	t.Cleanup(wellKnownServer.Close)

	// Create participants server
	participantsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := json.NewEncoder(w).Encode([]any{})
		require.NoError(t, err)
	}))
	t.Cleanup(participantsServer.Close)

	oauthClient := client.New(client.Config{
		ClientID:     "test-client",
		WellKnownURL: wellKnownServer.URL + "/.well-known/openid-configuration",
		MTLSClient:   parServer.Client(),
		JWTSigner:    newTestSigner(t),
	})

	cfg := tpp.Config{
		WellKnownURL:    wellKnownServer.URL + "/.well-known/openid-configuration",
		ClientID:        "test-client",
		RedirectURI:     "https://app.example/callback",
		ParticipantsURL: participantsServer.URL + "/participants",
		OAuthClient:     oauthClient,
	}

	ctx := context.Background()
	participantsCache, err := cache.NewParticipantCache(ctx, cfg.ParticipantsURL)
	require.NoError(t, err)

	tppInstance, err := tpp.NewWithContext(ctx, cfg, participantsCache)
	require.NoError(t, err)

	return tppInstance
}

func createTestTPPWithTokenServer(t *testing.T, tokenServer *httptest.Server) *tpp.TPP {
	t.Helper()

	// Create well-known server that points to our token server
	wellKnownServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 "https://auth.example",
			"authorization_endpoint": "https://auth.example/authorize",
			"mtls_endpoint_aliases": map[string]any{
				"pushed_authorization_request_endpoint": tokenServer.URL + "/par",
				"token_endpoint":                        tokenServer.URL + "/token",
				"introspection_endpoint":                tokenServer.URL + "/introspect",
			},
		})
		require.NoError(t, err)
	}))
	t.Cleanup(wellKnownServer.Close)

	// Create participants server
	participantsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := json.NewEncoder(w).Encode([]any{})
		require.NoError(t, err)
	}))
	t.Cleanup(participantsServer.Close)

	oauthClient := client.New(client.Config{
		ClientID:     "test-client",
		WellKnownURL: wellKnownServer.URL + "/.well-known/openid-configuration",
		MTLSClient:   tokenServer.Client(),
		JWTSigner:    newTestSigner(t),
	})

	cfg := tpp.Config{
		WellKnownURL:    wellKnownServer.URL + "/.well-known/openid-configuration",
		ClientID:        "test-client",
		RedirectURI:     "https://app.example/callback",
		ParticipantsURL: participantsServer.URL + "/participants",
		OAuthClient:     oauthClient,
	}

	ctx := context.Background()
	participantsCache, err := cache.NewParticipantCache(ctx, cfg.ParticipantsURL)
	require.NoError(t, err)

	tppInstance, err := tpp.NewWithContext(ctx, cfg, participantsCache)
	require.NoError(t, err)

	return tppInstance
}
