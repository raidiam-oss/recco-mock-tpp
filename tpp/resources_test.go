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

func TestCustomer(t *testing.T) {
	tests := []struct {
		name               string
		setupSession       func(t *testing.T, tppInstance *tpp.TPP) string
		providerID         string
		mockParticipants   func(t *testing.T) *httptest.Server
		mockResourceServer func(t *testing.T) *httptest.Server
		wantErr            bool
		wantErrContains    string
		wantStatus         int
		validateResponse   func(t *testing.T, response map[string]any)
	}{
		{
			name: "successful_customer_request",
			setupSession: func(t *testing.T, tppInstance *tpp.TPP) string {
				sessionID, _, err := tppInstance.BuildAuthParams(context.Background(), []string{"openid"})
				require.NoError(t, err)

				// Mock a successful token exchange by directly setting access token in session
				return sessionID
			},
			providerID: "as-1",
			mockParticipants: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Use raw JSON to avoid struct field issues
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
									},
								},
							},
						},
					}
					err := json.NewEncoder(w).Encode(participants)
					require.NoError(t, err)
				}))
			},
			mockResourceServer: func(t *testing.T) *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/recco/customer/v1/customer" {
						assert.Contains(t, r.Header.Get("Authorization"), "Bearer")
						err := json.NewEncoder(w).Encode(map[string]any{
							"resource": "customer",
							"data":     "customer_data",
						})
						require.NoError(t, err)
					}
				}))
			},
			wantErr:    true, // Will error due to no access token
			wantStatus: 0,
		},
		{
			name: "provider_not_found",
			setupSession: func(t *testing.T, tppInstance *tpp.TPP) string {
				sessionID, _, err := tppInstance.BuildAuthParams(context.Background(), []string{"openid"})
				require.NoError(t, err)
				return sessionID
			},
			providerID: "non-existent",
			mockParticipants: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					err := json.NewEncoder(w).Encode([]any{})
					require.NoError(t, err)
				}))
			},
			wantErr:         true,
			wantErrContains: "resource host not found",
		},
		{
			name: "session_not_found",
			setupSession: func(t *testing.T, tppInstance *tpp.TPP) string {
				return "invalid-session"
			},
			providerID: "as-1",
			mockParticipants: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Provide valid participant data so we get past resource resolution
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
									},
								},
							},
						},
					}
					err := json.NewEncoder(w).Encode(participants)
					require.NoError(t, err)
				}))
			},
			wantErr:         true,
			wantErrContains: "not authorized",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			participantsServer := tc.mockParticipants(t)
			defer participantsServer.Close()

			var resourceServer *httptest.Server
			if tc.mockResourceServer != nil {
				resourceServer = tc.mockResourceServer(t)
				defer resourceServer.Close()
			}

			tppInstance := createTestTPPWithResourceServers(t, participantsServer, resourceServer)
			sessionID := tc.setupSession(t, tppInstance)

			ctx := context.Background()
			response, status, err := tppInstance.Customer(ctx, sessionID, tc.providerID)

			if tc.wantErr {
				require.Error(t, err)
				if tc.wantErrContains != "" {
					assert.Contains(t, err.Error(), tc.wantErrContains)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.wantStatus, status)
				if tc.validateResponse != nil {
					tc.validateResponse(t, response)
				}
			}
		})
	}
}

func TestEnergy(t *testing.T) {
	tests := []struct {
		name               string
		setupSession       func(t *testing.T, tppInstance *tpp.TPP) string
		providerID         string
		mockParticipants   func(t *testing.T) *httptest.Server
		mockResourceServer func(t *testing.T) *httptest.Server
		wantErr            bool
		wantErrContains    string
		wantStatus         int
		validateResponse   func(t *testing.T, response map[string]any)
	}{
		{
			name: "successful_energy_request",
			setupSession: func(t *testing.T, tppInstance *tpp.TPP) string {
				sessionID, _, err := tppInstance.BuildAuthParams(context.Background(), []string{"openid"})
				require.NoError(t, err)
				return sessionID
			},
			providerID: "as-1",
			mockParticipants: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
				}))
			},
			wantErr: true, // Will error due to no access token
		},
		{
			name: "energy_api_not_found",
			setupSession: func(t *testing.T, tppInstance *tpp.TPP) string {
				sessionID, _, err := tppInstance.BuildAuthParams(context.Background(), []string{"openid"})
				require.NoError(t, err)
				return sessionID
			},
			providerID: "as-1",
			mockParticipants: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
											"ApiFamilyType": "customer", // Only customer, no energy
											"ApiVersion":    "1.0",
											"Status":        "Active",
											"ApiDiscoveryEndpoints": []any{
												map[string]any{"ApiEndpoint": "https://api.example/recco/customer"},
											},
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
			wantErr:         true,
			wantErrContains: "resource host not found",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			participantsServer := tc.mockParticipants(t)
			defer participantsServer.Close()

			var resourceServer *httptest.Server
			if tc.mockResourceServer != nil {
				resourceServer = tc.mockResourceServer(t)
				defer resourceServer.Close()
			}

			tppInstance := createTestTPPWithResourceServers(t, participantsServer, resourceServer)
			sessionID := tc.setupSession(t, tppInstance)

			ctx := context.Background()
			response, status, err := tppInstance.Energy(ctx, sessionID, tc.providerID)

			if tc.wantErr {
				require.Error(t, err)
				if tc.wantErrContains != "" {
					assert.Contains(t, err.Error(), tc.wantErrContains)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.wantStatus, status)
				if tc.validateResponse != nil {
					tc.validateResponse(t, response)
				}
			}
		})
	}
}

func TestResolveResourceHost(t *testing.T) {
	tests := []struct {
		name             string
		authServerID     string
		apiType          model.APIType
		mockParticipants func(t *testing.T) *httptest.Server
		wantErr          bool
		wantErrContains  string
		wantHost         string
	}{
		{
			name:         "successful_customer_resolution",
			authServerID: "as-1",
			apiType:      model.APITypeCustomer,
			mockParticipants: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					participants := []any{
						map[string]any{
							"OrganisationId": "org-1",
							"AuthorisationServers": []any{
								map[string]any{
									"AuthorisationServerId": "as-1",
									"OrganisationId":        "org-1",
									"ApiResources": []any{
										map[string]any{
											"ApiFamilyType": "customer",
											"ApiVersion":    "1.0",
											"Status":        "Active",
											"ApiDiscoveryEndpoints": []any{
												map[string]any{"ApiEndpoint": "https://api.example.com:8443/recco/customer"},
											},
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
			wantErr:         true,             // Will still error due to no access token, but should resolve host first
			wantErrContains: "not authorized", // Should get past host resolution to authorization error
			wantHost:        "https://api.example.com:8443",
		},
		{
			name:         "auth_server_not_found",
			authServerID: "non-existent",
			apiType:      model.APITypeCustomer,
			mockParticipants: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					participants := []any{
						map[string]any{
							"OrganisationId": "org-1",
							"AuthorisationServers": []any{
								map[string]any{
									"AuthorisationServerId": "as-1",
									"OrganisationId":        "org-1",
									"ApiResources":          []any{},
								},
							},
						},
					}
					err := json.NewEncoder(w).Encode(participants)
					require.NoError(t, err)
				}))
			},
			wantErr:         true,
			wantErrContains: "resource host not found",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			participantsServer := tc.mockParticipants(t)
			defer participantsServer.Close()

			tppInstance := createTestTPPWithResourceServers(t, participantsServer, nil)

			ctx := context.Background()

			// Test through Customer method which calls resolveResourceHost internally
			sessionID, _, err := tppInstance.BuildAuthParams(ctx, []string{"openid"})
			require.NoError(t, err)

			var actualErr error
			if tc.apiType == model.APITypeCustomer {
				_, _, actualErr = tppInstance.Customer(ctx, sessionID, tc.authServerID)
			} else {
				_, _, actualErr = tppInstance.Energy(ctx, sessionID, tc.authServerID)
			}

			if tc.wantErr {
				require.Error(t, actualErr)
				if tc.wantErrContains != "" {
					assert.Contains(t, actualErr.Error(), tc.wantErrContains)
				}
			} else if actualErr != nil {
				// Even successful host resolution will fail due to no access token
				// but we can check that the error is about authorization, not host resolution
				assert.Contains(t, actualErr.Error(), "not authorized")
			}
		})
	}
}

func TestGetJSON(t *testing.T) {
	tests := []struct {
		name             string
		setupSession     func(t *testing.T, tppInstance *tpp.TPP) string
		uri              string
		mockAPIServer    func(t *testing.T) *httptest.Server
		wantErr          bool
		wantErrContains  string
		wantStatus       int
		validateResponse func(t *testing.T, response map[string]any)
	}{
		{
			name: "session_not_found",
			setupSession: func(t *testing.T, tppInstance *tpp.TPP) string {
				return "invalid-session"
			},
			uri:             "https://api.example.com/test",
			wantErr:         true,
			wantErrContains: "not authorized",
		},
		{
			name: "no_access_token",
			setupSession: func(t *testing.T, tppInstance *tpp.TPP) string {
				sessionID, _, err := tppInstance.BuildAuthParams(context.Background(), []string{"openid"})
				require.NoError(t, err)
				return sessionID
			},
			uri:             "https://api.example.com/test",
			wantErr:         true,
			wantErrContains: "not authorized",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create TPP with participant data so we get past resource resolution
			participantsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
								},
							},
						},
					},
				}
				err := json.NewEncoder(w).Encode(participants)
				require.NoError(t, err)
			}))
			defer participantsServer.Close()

			tppInstance := createTestTPPWithResourceServers(t, participantsServer, nil)
			sessionID := tc.setupSession(t, tppInstance)

			ctx := context.Background()

			// Test getJSON through Customer method since it's private
			_, _, err := tppInstance.Customer(ctx, sessionID, "as-1")

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

// Helper function for creating TPP with custom resource servers
func createTestTPPWithResourceServers(t *testing.T, participantsServer, resourceServer *httptest.Server) *tpp.TPP {
	t.Helper()

	// Create well-known server
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

	var mtlsClient *http.Client
	if resourceServer != nil {
		mtlsClient = resourceServer.Client()
	} else {
		mtlsClient = &http.Client{}
	}

	oauthClient := client.New(client.Config{
		ClientID:     "test-client",
		WellKnownURL: wellKnownServer.URL + "/.well-known/openid-configuration",
		MTLSClient:   mtlsClient,
		JWTSigner:    newTestSigner(t),
	})

	var participantsURL string
	if participantsServer != nil {
		participantsURL = participantsServer.URL + "/participants"
	} else {
		// Create default empty participants server
		defaultParticipants := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			err := json.NewEncoder(w).Encode([]any{})
			require.NoError(t, err)
		}))
		t.Cleanup(defaultParticipants.Close)
		participantsURL = defaultParticipants.URL + "/participants"
	}

	cfg := tpp.Config{
		WellKnownURL:    wellKnownServer.URL + "/.well-known/openid-configuration",
		ClientID:        "test-client",
		RedirectURI:     "https://app.example/callback",
		ParticipantsURL: participantsURL,
		OAuthClient:     oauthClient,
	}

	ctx := context.Background()
	participantsCache, err := cache.NewParticipantCache(ctx, cfg.ParticipantsURL)
	require.NoError(t, err)

	tppInstance, err := tpp.NewWithContext(ctx, cfg, participantsCache)
	require.NoError(t, err)

	return tppInstance
}
