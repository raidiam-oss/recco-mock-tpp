package client_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/raidiam/recco-mock-tpp/shared/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name   string
		config client.Config
		want   func(t *testing.T, c *client.OAuthClient)
	}{
		{
			name: "creates_client_with_config",
			config: client.Config{
				ClientID:     "test-client",
				WellKnownURL: "https://auth.example/.well-known/openid-configuration",
				MTLSClient:   &http.Client{},
				JWTSigner:    createTestSigner(t),
			},
			want: func(t *testing.T, c *client.OAuthClient) {
				assert.NotNil(t, c)
				assert.NotNil(t, c.GetJWTSigner())
			},
		},
		{
			name: "creates_client_with_nil_values",
			config: client.Config{
				ClientID:     "",
				WellKnownURL: "",
				MTLSClient:   nil,
				JWTSigner:    nil,
			},
			want: func(t *testing.T, c *client.OAuthClient) {
				assert.NotNil(t, c)
				assert.Nil(t, c.GetJWTSigner())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := client.New(tc.config)
			tc.want(t, client)
		})
	}
}

func TestGetJWTSigner(t *testing.T) {
	tests := []struct {
		name    string
		signer  jose.Signer
		wantNil bool
	}{
		{
			name:    "returns_configured_signer",
			signer:  createTestSigner(t),
			wantNil: false,
		},
		{
			name:    "returns_nil_when_not_configured",
			signer:  nil,
			wantNil: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := client.Config{
				ClientID:     "test-client",
				WellKnownURL: "https://auth.example/.well-known/openid-configuration",
				MTLSClient:   &http.Client{},
				JWTSigner:    tc.signer,
			}

			client := client.New(config)
			result := client.GetJWTSigner()

			if tc.wantNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, tc.signer, result)
			}
		})
	}
}

func TestBuildClientAssertion(t *testing.T) {
	tests := []struct {
		name            string
		config          client.Config
		wantErr         bool
		wantErrContains string
		validateJWT     func(t *testing.T, jwt string)
	}{
		{
			name: "successful_assertion_build",
			config: client.Config{
				ClientID:     "test-client-123",
				WellKnownURL: "https://auth.example/.well-known/openid-configuration",
				MTLSClient:   &http.Client{},
				JWTSigner:    createTestSigner(t),
			},
			wantErr: false,
			validateJWT: func(t *testing.T, jwt string) {
				assert.NotEmpty(t, jwt)
				parts := strings.Split(jwt, ".")
				assert.Len(t, parts, 3, "JWT should have 3 parts")
			},
		},
		{
			name: "nil_signer_error",
			config: client.Config{
				ClientID:     "test-client",
				WellKnownURL: "https://auth.example/.well-known/openid-configuration",
				MTLSClient:   &http.Client{},
				JWTSigner:    nil,
			},
			wantErr:         true,
			wantErrContains: "jwt signer not configured",
		},
		{
			name: "invalid_well_known_url",
			config: client.Config{
				ClientID:     "test-client",
				WellKnownURL: "://invalid-url",
				MTLSClient:   &http.Client{},
				JWTSigner:    createTestSigner(t),
			},
			wantErr:         true,
			wantErrContains: "invalid well-known URL",
		},
		{
			name: "empty_well_known_url",
			config: client.Config{
				ClientID:     "test-client",
				WellKnownURL: "",
				MTLSClient:   &http.Client{},
				JWTSigner:    createTestSigner(t),
			},
			wantErr: false, // Empty URL is valid, results in empty scheme and host
			validateJWT: func(t *testing.T, jwt string) {
				assert.NotEmpty(t, jwt)
				parts := strings.Split(jwt, ".")
				assert.Len(t, parts, 3)
			},
		},
		{
			name: "different_client_id",
			config: client.Config{
				ClientID:     "different-client-456",
				WellKnownURL: "https://different.example/.well-known/openid-configuration",
				MTLSClient:   &http.Client{},
				JWTSigner:    createTestSigner(t),
			},
			wantErr: false,
			validateJWT: func(t *testing.T, jwt string) {
				assert.NotEmpty(t, jwt)
				// JWT should be different for different client IDs
				parts := strings.Split(jwt, ".")
				assert.Len(t, parts, 3)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := client.New(tc.config)

			jwt, err := client.BuildClientAssertion()

			if tc.wantErr {
				require.Error(t, err)
				if tc.wantErrContains != "" {
					assert.Contains(t, err.Error(), tc.wantErrContains)
				}
				assert.Empty(t, jwt)
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, jwt)
				if tc.validateJWT != nil {
					tc.validateJWT(t, jwt)
				}
			}
		})
	}
}

func TestGetJSON(t *testing.T) {
	tests := []struct {
		name             string
		accessToken      string
		setupServer      func(t *testing.T) *httptest.Server
		wantErr          bool
		wantErrContains  string
		wantStatusCode   int
		validateResponse func(t *testing.T, data map[string]any)
	}{
		{
			name:        "successful_json_request",
			accessToken: "valid-token-123",
			setupServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, "GET", r.Method)
					assert.Equal(t, "Bearer valid-token-123", r.Header.Get("Authorization"))

					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					err := json.NewEncoder(w).Encode(map[string]any{
						"data": "success",
						"id":   123,
					})
					require.NoError(t, err)
				}))
			},
			wantErr:        false,
			wantStatusCode: 200,
			validateResponse: func(t *testing.T, data map[string]any) {
				assert.Equal(t, "success", data["data"])
				assert.Equal(t, float64(123), data["id"]) // JSON numbers are float64
			},
		},
		{
			name:        "empty_access_token",
			accessToken: "",
			setupServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					t.Error("Server should not be called with empty access token")
				}))
			},
			wantErr:         true,
			wantErrContains: "access token required",
		},
		{
			name:        "server_error_response",
			accessToken: "valid-token",
			setupServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
					err := json.NewEncoder(w).Encode(map[string]any{
						"error": "internal server error",
					})
					require.NoError(t, err)
				}))
			},
			wantErr:        false, // GetJSON doesn't return error for non-2xx status
			wantStatusCode: 500,
			validateResponse: func(t *testing.T, data map[string]any) {
				assert.Equal(t, "internal server error", data["error"])
			},
		},
		{
			name:        "empty_response_body",
			accessToken: "valid-token",
			setupServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					// Empty body
				}))
			},
			wantErr:        false,
			wantStatusCode: 200,
			validateResponse: func(t *testing.T, data map[string]any) {
				assert.NotNil(t, data)
				assert.Len(t, data, 0) // Should be empty map
			},
		},
		{
			name:        "invalid_json_response",
			accessToken: "valid-token",
			setupServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					_, err := w.Write([]byte("{invalid json"))
					require.NoError(t, err)
				}))
			},
			wantErr:         true,
			wantErrContains: "decode json",
		},
		{
			name:        "unauthorized_response",
			accessToken: "invalid-token",
			setupServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusUnauthorized)
					err := json.NewEncoder(w).Encode(map[string]any{
						"error": "unauthorized",
					})
					require.NoError(t, err)
				}))
			},
			wantErr:        false, // GetJSON doesn't return error for non-2xx status
			wantStatusCode: 401,
			validateResponse: func(t *testing.T, data map[string]any) {
				assert.Equal(t, "unauthorized", data["error"])
			},
		},
		{
			name:        "large_json_response",
			accessToken: "valid-token",
			setupServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)

					// Create a larger response
					response := map[string]any{
						"items": make([]map[string]any, 100),
						"total": 100,
					}
					for i := range 100 {
						response["items"].([]map[string]any)[i] = map[string]any{
							"id":   i,
							"name": fmt.Sprintf("item-%d", i),
						}
					}

					err := json.NewEncoder(w).Encode(response)
					require.NoError(t, err)
				}))
			},
			wantErr:        false,
			wantStatusCode: 200,
			validateResponse: func(t *testing.T, data map[string]any) {
				assert.Equal(t, float64(100), data["total"])
				assert.Len(t, data["items"], 100)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := tc.setupServer(t)
			defer server.Close()

			config := client.Config{
				ClientID:     "test-client",
				WellKnownURL: "https://auth.example/.well-known/openid-configuration",
				MTLSClient:   server.Client(),
				JWTSigner:    createTestSigner(t),
			}

			client := client.New(config)
			ctx := context.Background()

			data, statusCode, err := client.GetJSON(ctx, server.URL, tc.accessToken)

			if tc.wantErr {
				require.Error(t, err)
				if tc.wantErrContains != "" {
					assert.Contains(t, err.Error(), tc.wantErrContains)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.wantStatusCode, statusCode)
				if tc.validateResponse != nil {
					tc.validateResponse(t, data)
				}
			}
		})
	}
}

func TestPostForm(t *testing.T) {
	tests := []struct {
		name            string
		formData        url.Values
		setupServer     func(t *testing.T) *httptest.Server
		wantErr         bool
		wantErrContains string
		validateRequest func(t *testing.T, r *http.Request)
	}{
		{
			name: "successful_form_post",
			formData: url.Values{
				"grant_type": {"authorization_code"},
				"code":       {"test-code-123"},
				"client_id":  {"test-client"},
			},
			setupServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, "POST", r.Method)
					assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

					err := r.ParseForm()
					require.NoError(t, err)
					assert.Equal(t, "authorization_code", r.Form.Get("grant_type"))
					assert.Equal(t, "test-code-123", r.Form.Get("code"))
					assert.Equal(t, "test-client", r.Form.Get("client_id"))

					w.WriteHeader(http.StatusOK)
					_, err = w.Write([]byte(`{"access_token": "token123"}`))
					require.NoError(t, err)
				}))
			},
			wantErr: false,
		},
		{
			name:     "empty_form_data",
			formData: url.Values{},
			setupServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, "POST", r.Method)
					assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

					err := r.ParseForm()
					require.NoError(t, err)
					assert.Len(t, r.Form, 0)

					w.WriteHeader(http.StatusBadRequest)
				}))
			},
			wantErr: false,
		},
		{
			name: "special_characters_in_form",
			formData: url.Values{
				"redirect_uri": {"https://app.example/callback?param=value&other=test"},
				"scope":        {"openid profile email"},
				"state":        {"abc123!@#$%^&*()"},
			},
			setupServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					err := r.ParseForm()
					require.NoError(t, err)
					assert.Equal(t, "https://app.example/callback?param=value&other=test", r.Form.Get("redirect_uri"))
					assert.Equal(t, "openid profile email", r.Form.Get("scope"))
					assert.Equal(t, "abc123!@#$%^&*()", r.Form.Get("state"))

					w.WriteHeader(http.StatusOK)
				}))
			},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := tc.setupServer(t)
			defer server.Close()

			config := client.Config{
				ClientID:     "test-client",
				WellKnownURL: "https://auth.example/.well-known/openid-configuration",
				MTLSClient:   server.Client(),
				JWTSigner:    createTestSigner(t),
			}

			client := client.New(config)
			ctx := context.Background()

			resp, err := client.PostForm(ctx, server.URL, tc.formData)

			if tc.wantErr {
				require.Error(t, err)
				if tc.wantErrContains != "" {
					assert.Contains(t, err.Error(), tc.wantErrContains)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				resp.Body.Close()
			}
		})
	}
}

func TestPostFormWithClientAssertion(t *testing.T) {
	tests := []struct {
		name            string
		formData        url.Values
		config          client.Config
		setupServer     func(t *testing.T) *httptest.Server
		wantErr         bool
		wantErrContains string
	}{
		{
			name: "successful_post_with_assertion",
			formData: url.Values{
				"grant_type": {"authorization_code"},
				"code":       {"test-code"},
			},
			config: client.Config{
				ClientID:     "test-client",
				WellKnownURL: "https://auth.example/.well-known/openid-configuration",
				JWTSigner:    createTestSigner(t),
			},
			setupServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					err := r.ParseForm()
					require.NoError(t, err)

					// Check original form data
					assert.Equal(t, "authorization_code", r.Form.Get("grant_type"))
					assert.Equal(t, "test-code", r.Form.Get("code"))

					// Check client assertion was added
					assert.NotEmpty(t, r.Form.Get("client_assertion"))
					assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", r.Form.Get("client_assertion_type"))

					// Validate JWT format
					jwt := r.Form.Get("client_assertion")
					parts := strings.Split(jwt, ".")
					assert.Len(t, parts, 3)

					w.WriteHeader(http.StatusOK)
				}))
			},
			wantErr: false,
		},
		{
			name: "nil_signer_error",
			formData: url.Values{
				"grant_type": {"client_credentials"},
			},
			config: client.Config{
				ClientID:     "test-client",
				WellKnownURL: "https://auth.example/.well-known/openid-configuration",
				JWTSigner:    nil, // No signer configured
			},
			setupServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					t.Error("Server should not be called when assertion building fails")
				}))
			},
			wantErr:         true,
			wantErrContains: "jwt signer not configured",
		},
		{
			name: "invalid_well_known_url",
			formData: url.Values{
				"grant_type": {"client_credentials"},
			},
			config: client.Config{
				ClientID:     "test-client",
				WellKnownURL: "://invalid-url",
				JWTSigner:    createTestSigner(t),
			},
			setupServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					t.Error("Server should not be called when assertion building fails")
				}))
			},
			wantErr:         true,
			wantErrContains: "invalid well-known URL",
		},
		{
			name:     "empty_form_with_assertion",
			formData: url.Values{},
			config: client.Config{
				ClientID:     "test-client",
				WellKnownURL: "https://auth.example/.well-known/openid-configuration",
				JWTSigner:    createTestSigner(t),
			},
			setupServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					err := r.ParseForm()
					require.NoError(t, err)

					// Should have client assertion even with empty original form
					assert.NotEmpty(t, r.Form.Get("client_assertion"))
					assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", r.Form.Get("client_assertion_type"))

					w.WriteHeader(http.StatusOK)
				}))
			},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := tc.setupServer(t)
			defer server.Close()

			// Set MTLSClient to server client
			tc.config.MTLSClient = server.Client()

			client := client.New(tc.config)
			ctx := context.Background()

			resp, err := client.PostFormWithClientAssertion(ctx, server.URL, tc.formData)

			if tc.wantErr {
				require.Error(t, err)
				if tc.wantErrContains != "" {
					assert.Contains(t, err.Error(), tc.wantErrContains)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				resp.Body.Close()
			}
		})
	}
}

func TestRandAlphaNum(t *testing.T) {
	// Since randAlphaNum is not exported, we test it indirectly through BuildClientAssertion
	// by checking that JTI claims are different between calls

	config := client.Config{
		ClientID:     "test-client",
		WellKnownURL: "https://auth.example/.well-known/openid-configuration",
		MTLSClient:   &http.Client{},
		JWTSigner:    createTestSigner(t),
	}

	client := client.New(config)

	// Generate multiple JWTs and ensure they're different (due to different JTI values)
	jwts := make([]string, 10)
	for i := range 10 {
		jwt, err := client.BuildClientAssertion()
		require.NoError(t, err)
		jwts[i] = jwt
	}

	// All JWTs should be different
	seen := make(map[string]bool)
	for _, jwt := range jwts {
		assert.False(t, seen[jwt], "JWT should be unique: %s", jwt)
		seen[jwt] = true
	}
}

// Helper functions

func createTestSigner(t *testing.T) jose.Signer {
	t.Helper()

	// Generate RSA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create signer
	opts := (&jose.SignerOptions{}).WithType("JWT")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS256, Key: key}, opts)
	require.NoError(t, err)

	return signer
}
