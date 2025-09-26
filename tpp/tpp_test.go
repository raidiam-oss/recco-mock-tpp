package tpp_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/raidiam/recco-mock-tpp/shared/cache"
	"github.com/raidiam/recco-mock-tpp/shared/client"
	"github.com/raidiam/recco-mock-tpp/tpp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewWithContext(t *testing.T) {
	tests := []struct {
		name                string
		config              tpp.Config
		mockWellKnownServer func(t *testing.T) *httptest.Server
		mockParticipants    func(t *testing.T) *httptest.Server
		wantErr             bool
		wantErrContains     string
		validateTPP         func(t *testing.T, tppInstance *tpp.TPP)
	}{
		{
			name: "successful_initialization",
			mockWellKnownServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, "/.well-known/openid-configuration", r.URL.Path)
					response := map[string]any{
						"issuer":                 "https://auth.example.com",
						"authorization_endpoint": "https://auth.example.com/authorize",
						"token_endpoint":         "https://auth.example.com/token",
						"jwks_uri":               "https://auth.example.com/jwks",
						"mtls_endpoint_aliases": map[string]any{
							"pushed_authorization_request_endpoint": "https://mtls.example.com/par",
							"token_endpoint":                        "https://mtls.example.com/token",
							"introspection_endpoint":                "https://mtls.example.com/introspect",
						},
					}
					err := json.NewEncoder(w).Encode(response)
					require.NoError(t, err)
				}))
			},
			mockParticipants: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					err := json.NewEncoder(w).Encode([]any{})
					require.NoError(t, err)
				}))
			},
			wantErr: false,
			validateTPP: func(t *testing.T, tppInstance *tpp.TPP) {
				assert.NotNil(t, tppInstance)
				assert.NotNil(t, tppInstance.Providers)
			},
		},
		{
			name: "well_known_server_error",
			mockWellKnownServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}))
			},
			mockParticipants: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					err := json.NewEncoder(w).Encode([]any{})
					require.NoError(t, err)
				}))
			},
			wantErr:         true,
			wantErrContains: "well-known configuration returned status",
		},
		{
			name: "well_known_invalid_json",
			mockWellKnownServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, err := w.Write([]byte("invalid json"))
					require.NoError(t, err)
				}))
			},
			mockParticipants: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					err := json.NewEncoder(w).Encode([]any{})
					require.NoError(t, err)
				}))
			},
			wantErr:         true,
			wantErrContains: "failed to decode well-known configuration",
		},
		{
			name: "well_known_server_not_reachable",
			mockWellKnownServer: func(t *testing.T) *httptest.Server {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
				server.Close() // Close immediately to make it unreachable
				return server
			},
			mockParticipants: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					err := json.NewEncoder(w).Encode([]any{})
					require.NoError(t, err)
				}))
			},
			wantErr:         true,
			wantErrContains: "failed to fetch well-known configuration",
		},
		{
			name: "participants_cache_error",
			mockWellKnownServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					response := map[string]any{
						"issuer":                 "https://auth.example.com",
						"authorization_endpoint": "https://auth.example.com/authorize",
						"token_endpoint":         "https://auth.example.com/token",
					}
					err := json.NewEncoder(w).Encode(response)
					require.NoError(t, err)
				}))
			},
			mockParticipants: func(t *testing.T) *httptest.Server {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
				server.Close() // Close to make participants unreachable
				return server
			},
			wantErr:         true,
			wantErrContains: "", // Error will come from cache creation, not TPP creation
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wellKnownServer := tc.mockWellKnownServer(t)
			defer wellKnownServer.Close()

			participantsServer := tc.mockParticipants(t)
			defer participantsServer.Close()

			oauthClient := client.New(client.Config{
				ClientID:     "test-client-id",
				WellKnownURL: wellKnownServer.URL + "/.well-known/openid-configuration",
				MTLSClient:   &http.Client{Timeout: 30 * time.Second},
				JWTSigner:    newTestSigner(t),
			})

			cfg := tpp.Config{
				WellKnownURL:    wellKnownServer.URL + "/.well-known/openid-configuration",
				ClientID:        "test-client-id",
				RedirectURI:     "https://app.example.com/callback",
				ParticipantsURL: participantsServer.URL + "/participants",
				OAuthClient:     oauthClient,
			}

			ctx := context.Background()

			// Create participants cache first
			participantsCache, err := cache.NewParticipantCache(ctx, cfg.ParticipantsURL)
			if tc.name == "participants_cache_error" {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			tppInstance, err := tpp.NewWithContext(ctx, cfg, participantsCache)

			if tc.wantErr {
				require.Error(t, err)
				if tc.wantErrContains != "" {
					assert.Contains(t, err.Error(), tc.wantErrContains)
				}
			} else {
				require.NoError(t, err)
				tc.validateTPP(t, tppInstance)
			}
		})
	}
}

func TestTPPConfig(t *testing.T) {
	tests := []struct {
		name       string
		config     tpp.Config
		wantValid  bool
		wantFields map[string]any
	}{
		{
			name: "complete_config",
			config: tpp.Config{
				WellKnownURL:    "https://auth.example.com/.well-known/openid-configuration",
				ClientID:        "test-client",
				RedirectURI:     "https://app.example.com/callback",
				ParticipantsURL: "https://directory.example.com/participants",
				OAuthClient: client.New(client.Config{
					ClientID:     "test-client",
					WellKnownURL: "https://auth.example.com/.well-known/openid-configuration",
					MTLSClient:   &http.Client{},
					JWTSigner:    newTestSigner(t),
				}),
			},
			wantValid: true,
			wantFields: map[string]any{
				"WellKnownURL":    "https://auth.example.com/.well-known/openid-configuration",
				"ClientID":        "test-client",
				"RedirectURI":     "https://app.example.com/callback",
				"ParticipantsURL": "https://directory.example.com/participants",
			},
		},
		{
			name: "minimal_config",
			config: tpp.Config{
				WellKnownURL:    "https://auth.example.com/.well-known/openid-configuration",
				ClientID:        "minimal-client",
				RedirectURI:     "https://app.example.com/callback",
				ParticipantsURL: "https://directory.example.com/participants",
				OAuthClient:     nil, // This should cause issues when used
			},
			wantValid: true, // Config itself is valid, but usage will fail
			wantFields: map[string]any{
				"WellKnownURL":    "https://auth.example.com/.well-known/openid-configuration",
				"ClientID":        "minimal-client",
				"RedirectURI":     "https://app.example.com/callback",
				"ParticipantsURL": "https://directory.example.com/participants",
			},
		},
		{
			name:      "empty_config",
			config:    tpp.Config{},
			wantValid: false, // Will fail when trying to create TPP
			wantFields: map[string]any{
				"WellKnownURL":    "",
				"ClientID":        "",
				"RedirectURI":     "",
				"ParticipantsURL": "",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Validate config structure
			assert.Equal(t, tc.wantFields["WellKnownURL"], tc.config.WellKnownURL)
			assert.Equal(t, tc.wantFields["ClientID"], tc.config.ClientID)
			assert.Equal(t, tc.wantFields["RedirectURI"], tc.config.RedirectURI)
			assert.Equal(t, tc.wantFields["ParticipantsURL"], tc.config.ParticipantsURL)

			if tc.wantValid && tc.config.WellKnownURL != "" {
				// Try to use the config with a mock server
				wellKnownServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					response := map[string]any{
						"issuer":                 "https://auth.example.com",
						"authorization_endpoint": "https://auth.example.com/authorize",
					}
					err := json.NewEncoder(w).Encode(response)
					require.NoError(t, err)
				}))
				defer wellKnownServer.Close()

				participantsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					err := json.NewEncoder(w).Encode([]any{})
					require.NoError(t, err)
				}))
				defer participantsServer.Close()

				// Update config with test server URLs
				testConfig := tc.config
				testConfig.WellKnownURL = wellKnownServer.URL + "/.well-known/openid-configuration"
				testConfig.ParticipantsURL = participantsServer.URL + "/participants"

				if testConfig.OAuthClient != nil {
					ctx := context.Background()
					participantsCache, err := cache.NewParticipantCache(ctx, testConfig.ParticipantsURL)
					require.NoError(t, err)

					_, err = tpp.NewWithContext(ctx, testConfig, participantsCache)
					assert.NoError(t, err)
				}
			}
		})
	}
}

func TestTPPSessionManagement(t *testing.T) {
	tests := []struct {
		name           string
		setupSessions  func(t *testing.T, tppInstance *tpp.TPP) []string
		testOperations func(t *testing.T, tppInstance *tpp.TPP, sessionIDs []string)
	}{
		{
			name: "multiple_concurrent_sessions",
			setupSessions: func(t *testing.T, tppInstance *tpp.TPP) []string {
				ctx := context.Background()
				var sessionIDs []string

				// Create multiple sessions
				for range 5 {
					sessionID, _, err := tppInstance.BuildAuthParams(ctx, []string{"openid"})
					require.NoError(t, err)
					sessionIDs = append(sessionIDs, sessionID)
				}

				return sessionIDs
			},
			testOperations: func(t *testing.T, tppInstance *tpp.TPP, sessionIDs []string) {
				ctx := context.Background()

				// Verify all sessions are independent
				for i, sessionID := range sessionIDs {
					// Each session should have different auth params
					_, output, err := tppInstance.BuildAuthParams(ctx, []string{"openid", "customer"})
					require.NoError(t, err)

					// Try to use the original session ID for token exchange (should fail due to state mismatch)
					_, err = tppInstance.ExchangeToken(ctx, sessionID, "code", "wrong-state")
					assert.Error(t, err)
					assert.Contains(t, err.Error(), "invalid state")

					// Verify session isolation by checking different scopes
					_, newOutput, err := tppInstance.BuildAuthParams(ctx, []string{})
					require.NoError(t, err)

					// Different sessions should have different states
					if i > 0 {
						assert.NotEqual(t, output.State, newOutput.State)
					}
				}
			},
		},
		{
			name: "session_state_persistence",
			setupSessions: func(t *testing.T, tppInstance *tpp.TPP) []string {
				ctx := context.Background()
				sessionID, _, err := tppInstance.BuildAuthParams(ctx, []string{"openid", "customer", "energy"})
				require.NoError(t, err)
				return []string{sessionID}
			},
			testOperations: func(t *testing.T, tppInstance *tpp.TPP, sessionIDs []string) {
				ctx := context.Background()
				sessionID := sessionIDs[0]

				// Build auth params again with same session should work
				_, output1, err := tppInstance.BuildAuthParams(ctx, []string{"openid"})
				require.NoError(t, err)

				_, output2, err := tppInstance.BuildAuthParams(ctx, []string{"openid", "profile"})
				require.NoError(t, err)

				// Each call creates a new session, so states should be different
				assert.NotEqual(t, output1.State, output2.State)

				// Original session should still exist and be usable
				// (though it will fail due to no actual OAuth server)
				_, err = tppInstance.ExchangeToken(ctx, sessionID, "code", "wrong-state")
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid state")
			},
		},
		{
			name: "invalid_session_operations",
			setupSessions: func(t *testing.T, tppInstance *tpp.TPP) []string {
				return []string{"invalid-session-id"}
			},
			testOperations: func(t *testing.T, tppInstance *tpp.TPP, sessionIDs []string) {
				ctx := context.Background()
				invalidSessionID := sessionIDs[0]

				// Try to exchange token with invalid session
				_, err := tppInstance.ExchangeToken(ctx, invalidSessionID, "code", "state")
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "session not found")

				// Try to access customer data with invalid session
				_, _, err = tppInstance.Customer(ctx, invalidSessionID, "as-1")
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "not authorized")

				// Try to access energy data with invalid session
				_, _, err = tppInstance.Energy(ctx, invalidSessionID, "as-1")
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "not authorized")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create TPP with participant data for resource operations
			participantsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				participants := []any{
					map[string]any{
						"OrganisationId":   "org-1",
						"OrganisationName": "Test Org",
						"AuthorisationServers": []any{
							map[string]any{
								"AuthorisationServerId": "as-1",
								"OrganisationId":        "org-1",
								"CustomerFriendlyName":  "Test Provider",
								"ApiResources": []any{
									map[string]any{
										"ApiFamilyType": "customer",
										"ApiVersion":    "1.0",
										"Status":        "Active",
										"ApiDiscoveryEndpoints": []any{
											map[string]any{"ApiEndpoint": "https://api.example/recco/customer"},
										},
									},
									map[string]any{
										"ApiFamilyType": "energy",
										"ApiVersion":    "1.0",
										"Status":        "Active",
										"ApiDiscoveryEndpoints": []any{
											map[string]any{"ApiEndpoint": "https://api.example/recco/energy"},
										},
									},
								},
							},
						},
					},
				}
				err := json.NewEncoder(w).Encode(participants)
				require.NoError(t, err)
			})

			tppInstance := createTestTPPWithCustomServers(t, nil, participantsHandler, nil)
			sessionIDs := tc.setupSessions(t, tppInstance)
			tc.testOperations(t, tppInstance, sessionIDs)
		})
	}
}

func TestTPPProviderIntegration(t *testing.T) {
	tests := []struct {
		name              string
		mockParticipants  func(t *testing.T) *httptest.Server
		validateProviders func(t *testing.T, tppInstance *tpp.TPP)
	}{
		{
			name: "providers_cache_integration",
			mockParticipants: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					participants := []any{
						map[string]any{
							"OrganisationId":   "org-1",
							"OrganisationName": "Test Bank",
							"AuthorisationServers": []any{
								map[string]any{
									"AuthorisationServerId": "as-1",
									"OrganisationId":        "org-1",
									"CustomerFriendlyName":  "Test Bank OIDC",
									"ApiResources": []any{
										map[string]any{
											"ApiFamilyType": "customer",
											"ApiVersion":    "1.0",
											"Status":        "Active",
										},
									},
								},
							},
						},
					}
					err := json.NewEncoder(w).Encode(participants)
					require.NoError(t, err)
				}))
			},
			validateProviders: func(t *testing.T, tppInstance *tpp.TPP) {
				assert.NotNil(t, tppInstance.Providers)

				authServers := tppInstance.Providers.AuthServers()
				assert.NotNil(t, authServers)
				// The auth servers list should be available through the cache
			},
		},
		{
			name: "empty_participants",
			mockParticipants: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					err := json.NewEncoder(w).Encode([]any{})
					require.NoError(t, err)
				}))
			},
			validateProviders: func(t *testing.T, tppInstance *tpp.TPP) {
				assert.NotNil(t, tppInstance.Providers)

				authServers := tppInstance.Providers.AuthServers()
				assert.NotNil(t, authServers)
				assert.Empty(t, authServers)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			participantsServer := tc.mockParticipants(t)
			defer participantsServer.Close()

			wellKnownServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				response := map[string]any{
					"issuer":                 "https://auth.example.com",
					"authorization_endpoint": "https://auth.example.com/authorize",
				}
				err := json.NewEncoder(w).Encode(response)
				require.NoError(t, err)
			}))
			defer wellKnownServer.Close()

			oauthClient := client.New(client.Config{
				ClientID:     "test-client",
				WellKnownURL: wellKnownServer.URL + "/.well-known/openid-configuration",
				MTLSClient:   &http.Client{},
				JWTSigner:    newTestSigner(t),
			})

			cfg := tpp.Config{
				WellKnownURL:    wellKnownServer.URL + "/.well-known/openid-configuration",
				ClientID:        "test-client",
				RedirectURI:     "https://app.example.com/callback",
				ParticipantsURL: participantsServer.URL + "/participants",
				OAuthClient:     oauthClient,
			}

			ctx := context.Background()
			participantsCache, err := cache.NewParticipantCache(ctx, cfg.ParticipantsURL)
			require.NoError(t, err)

			tppInstance, err := tpp.NewWithContext(ctx, cfg, participantsCache)
			require.NoError(t, err)

			tc.validateProviders(t, tppInstance)
		})
	}
}

func TestTPPTimeout(t *testing.T) {
	tests := []struct {
		name            string
		setupMockServer func(t *testing.T) *httptest.Server
		contextTimeout  time.Duration
		wantErr         bool
		wantErrContains string
	}{
		{
			name: "well_known_timeout",
			setupMockServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Simulate slow response
					time.Sleep(100 * time.Millisecond)
					response := map[string]any{
						"issuer": "https://auth.example.com",
					}
					err := json.NewEncoder(w).Encode(response)
					require.NoError(t, err)
				}))
			},
			contextTimeout:  50 * time.Millisecond, // Shorter than server response time
			wantErr:         true,
			wantErrContains: "context deadline exceeded",
		},
		{
			name: "well_known_success_within_timeout",
			setupMockServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					response := map[string]any{
						"issuer":                 "https://auth.example.com",
						"authorization_endpoint": "https://auth.example.com/authorize",
					}
					err := json.NewEncoder(w).Encode(response)
					require.NoError(t, err)
				}))
			},
			contextTimeout: 1 * time.Second,
			wantErr:        false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wellKnownServer := tc.setupMockServer(t)
			defer wellKnownServer.Close()

			participantsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				err := json.NewEncoder(w).Encode([]any{})
				require.NoError(t, err)
			}))
			defer participantsServer.Close()

			oauthClient := client.New(client.Config{
				ClientID:     "test-client",
				WellKnownURL: wellKnownServer.URL + "/.well-known/openid-configuration",
				MTLSClient:   &http.Client{},
				JWTSigner:    newTestSigner(t),
			})

			cfg := tpp.Config{
				WellKnownURL:    wellKnownServer.URL + "/.well-known/openid-configuration",
				ClientID:        "test-client",
				RedirectURI:     "https://app.example.com/callback",
				ParticipantsURL: participantsServer.URL + "/participants",
				OAuthClient:     oauthClient,
			}

			ctx, cancel := context.WithTimeout(context.Background(), tc.contextTimeout)
			defer cancel()

			participantsCache, err := cache.NewParticipantCache(context.Background(), cfg.ParticipantsURL)
			require.NoError(t, err)

			_, err = tpp.NewWithContext(ctx, cfg, participantsCache)

			if tc.wantErr {
				require.Error(t, err)
				if tc.wantErrContains != "" {
					assert.Contains(t, err.Error(), tc.wantErrContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// testBackends provides a complete mock backend setup for integration testing
type testBackends struct {
	httpSrv          *httptest.Server // well-known + participants
	tlsSrv           *httptest.Server // PAR + token + introspect + resource APIs
	tpp              *tpp.TPP
	wellKnownHits    atomic.Int64
	participantsHits atomic.Int64
}

// newTestSigner creates a test JWT signer for testing
func newTestSigner(t *testing.T) jose.Signer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	opts := (&jose.SignerOptions{}).WithType("JWT")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS256, Key: priv}, opts)
	require.NoError(t, err)
	return signer
}

// newTestBackends creates a complete test environment with mock OAuth and resource servers
func newTestBackends(t *testing.T) *testBackends {
	t.Helper()

	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	// TLS server for mTLS endpoints (PAR, token, introspect, resource APIs)
	tlsMux := http.NewServeMux()
	tlsMux.HandleFunc("/par", func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		require.NoError(t, err)
		require.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", r.Form.Get("client_assertion_type"))
		require.NotEmpty(t, r.Form.Get("client_assertion"))
		require.NotEmpty(t, r.Form.Get("request"))

		err = json.NewEncoder(w).Encode(map[string]any{
			"expires_in":  90,
			"request_uri": "urn:ietf:params:oauth:request_uri:TESTPAR",
		})
		require.NoError(t, err)
	})
	tlsMux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		require.NoError(t, err)
		require.Equal(t, "authorization_code", r.Form.Get("grant_type"))
		require.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", r.Form.Get("client_assertion_type"))
		require.NotEmpty(t, r.Form.Get("client_assertion"))
		require.NotEmpty(t, r.Form.Get("code_verifier"))

		if r.Form.Get("code") == "bad" {
			w.WriteHeader(http.StatusBadRequest)
			err = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"})
			require.NoError(t, err)
			return
		}
		err = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "AT",
			"id_token":     "header.payload.sig",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
		require.NoError(t, err)
	})
	tlsMux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		require.NoError(t, err)
		require.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", r.Form.Get("client_assertion_type"))
		require.NotEmpty(t, r.Form.Get("client_assertion"))
		require.NotEmpty(t, r.Form.Get("token"))

		err = json.NewEncoder(w).Encode(map[string]any{
			"active": true,
			"scope":  "openid customer energy",
		})
		require.NoError(t, err)
	})
	tlsMux.HandleFunc("/recco/customer/v1/customer", func(w http.ResponseWriter, r *http.Request) {
		err := json.NewEncoder(w).Encode(map[string]any{"resource": "customer"})
		require.NoError(t, err)
	})
	tlsMux.HandleFunc("/recco/energy/v1/energy", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		err := json.NewEncoder(w).Encode(map[string]any{"message": "scope not allowed"})
		require.NoError(t, err)
	})
	tlsSrv := httptest.NewTLSServer(tlsMux)
	t.Cleanup(tlsSrv.Close)

	tlsURL, err := url.Parse(tlsSrv.URL)
	require.NoError(t, err)
	tlsHost := tlsURL.Host

	// HTTP server for discovery endpoints
	tb := &testBackends{}
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		tb.wellKnownHits.Add(1)
		err := json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 "https://auth.example",
			"authorization_endpoint": "https://auth.example/authorize",
			"mtls_endpoint_aliases": map[string]any{
				"pushed_authorization_request_endpoint": tlsSrv.URL + "/par",
				"token_endpoint":                        tlsSrv.URL + "/token",
				"introspection_endpoint":                tlsSrv.URL + "/introspect",
			},
		})
		require.NoError(t, err)
	})
	httpMux.HandleFunc("/participants", func(w http.ResponseWriter, r *http.Request) {
		tb.participantsHits.Add(1)
		payload := []any{
			map[string]any{
				"OrganisationId":   "org-1",
				"OrganisationName": "Org One",
				"AuthorisationServers": []any{
					map[string]any{
						"AuthorisationServerId":   "as-1",
						"OrganisationId":          "org-1",
						"CustomerFriendlyName":    "Provider One",
						"OpenIDDiscoveryDocument": "https://idp.example/.well-known/openid-configuration",
						"ApiResources": []any{
							map[string]any{
								"ApiFamilyType": "customer",
								"ApiVersion":    "1.0",
								"Status":        "Active",
								"ApiDiscoveryEndpoints": []any{
									map[string]any{"ApiEndpoint": "https://" + tlsHost + "/recco/customer"},
								},
							},
							map[string]any{
								"ApiFamilyType": "energy",
								"ApiVersion":    "1.0",
								"Status":        "Active",
								"ApiDiscoveryEndpoints": []any{
									map[string]any{"ApiEndpoint": "https://" + tlsHost + "/recco/energy"},
								},
							},
						},
					},
				},
			},
		}
		err := json.NewEncoder(w).Encode(payload)
		require.NoError(t, err)
	})
	httpSrv := httptest.NewServer(httpMux)
	t.Cleanup(httpSrv.Close)

	cli := tlsSrv.Client()
	if tr, ok := cli.Transport.(*http.Transport); ok {
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
		}
		tr.IdleConnTimeout = 10 * time.Second
	}

	oauthClient := client.New(client.Config{
		ClientID:     "test-client",
		WellKnownURL: httpSrv.URL + "/.well-known/openid-configuration",
		MTLSClient:   cli,
		JWTSigner:    newTestSigner(t),
	})
	cfg := tpp.Config{
		WellKnownURL:    httpSrv.URL + "/.well-known/openid-configuration",
		ClientID:        "test-client",
		RedirectURI:     "https://app.example/callback",
		ParticipantsURL: httpSrv.URL + "/participants",
		OAuthClient:     oauthClient,
	}
	tb.httpSrv = httpSrv
	tb.tlsSrv = tlsSrv

	// Initialize TPP with context to fetch OpenID configuration
	ctx := context.Background()
	participantsCache, err := cache.NewParticipantCache(ctx, cfg.ParticipantsURL)
	require.NoError(t, err)
	tppInstance, err := tpp.NewWithContext(ctx, cfg, participantsCache)
	require.NoError(t, err)
	tb.tpp = tppInstance
	return tb
}

// createSimpleTestTPP creates a minimal TPP instance for unit testing
func createSimpleTestTPP(t *testing.T) *tpp.TPP {
	t.Helper()

	// Create a simple well-known server
	wellKnownServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 "https://auth.example",
			"authorization_endpoint": "https://auth.example/authorize",
			"mtls_endpoint_aliases": map[string]any{
				"pushed_authorization_request_endpoint": "https://mtls.example/par",
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
		MTLSClient:   &http.Client{Timeout: 30 * time.Second},
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

// createTestTPPWithCustomServers creates TPP with custom mock servers for specific testing scenarios
func createTestTPPWithCustomServers(t *testing.T, wellKnownHandler, participantsHandler, mtlsHandler http.HandlerFunc) *tpp.TPP {
	t.Helper()

	var wellKnownServer, participantsServer, mtlsServer *httptest.Server

	if wellKnownHandler != nil {
		wellKnownServer = httptest.NewServer(wellKnownHandler)
		t.Cleanup(wellKnownServer.Close)
	}

	if participantsHandler != nil {
		participantsServer = httptest.NewServer(participantsHandler)
		t.Cleanup(participantsServer.Close)
	}

	var mtlsClient *http.Client
	if mtlsHandler != nil {
		mtlsServer = httptest.NewTLSServer(mtlsHandler)
		t.Cleanup(mtlsServer.Close)
		mtlsClient = mtlsServer.Client()
	} else {
		mtlsClient = &http.Client{Timeout: 30 * time.Second}
	}

	// Use default handlers if not provided
	if wellKnownServer == nil {
		wellKnownServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			err := json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 "https://auth.example",
				"authorization_endpoint": "https://auth.example/authorize",
				"mtls_endpoint_aliases": map[string]any{
					"pushed_authorization_request_endpoint": "https://mtls.example/par",
					"token_endpoint":                        "https://mtls.example/token",
					"introspection_endpoint":                "https://mtls.example/introspect",
				},
			})
			require.NoError(t, err)
		}))
		t.Cleanup(wellKnownServer.Close)
	}

	if participantsServer == nil {
		participantsServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			err := json.NewEncoder(w).Encode([]any{})
			require.NoError(t, err)
		}))
		t.Cleanup(participantsServer.Close)
	}

	oauthClient := client.New(client.Config{
		ClientID:     "test-client",
		WellKnownURL: wellKnownServer.URL + "/.well-known/openid-configuration",
		MTLSClient:   mtlsClient,
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
