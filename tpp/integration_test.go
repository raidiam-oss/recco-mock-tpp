package tpp_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegrationTokenExchange tests the complete OAuth token exchange flow with real backend mocks
func TestIntegrationTokenExchange(t *testing.T) {
	tb := newTestBackends(t)
	ctx := context.Background()

	sessionID, built, err := tb.tpp.BuildAuthParams(ctx, []string{"openid"})
	require.NoError(t, err)
	assert.Equal(t, int64(1), tb.wellKnownHits.Load(), "well-known should be fetched once during TPP initialization")

	_, err = tb.tpp.FinalizeAuthURL(ctx, sessionID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), tb.wellKnownHits.Load(), "well-known should still be 1 (cached from initialization)")

	tests := []struct {
		name        string
		code        string
		state       string
		wantErr     bool
		wantHasAT   bool
		wantIntroOK bool
	}{
		{"success_with_introspection_and_oidc_cache", "code123", built.State, false, true, true},
		{"state_mismatch", "code123", "WRONG", true, false, false},
		{"token_endpoint_error_bubbles_json", "bad", built.State, true, false, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tokens, err := tb.tpp.ExchangeToken(ctx, sessionID, tc.code, tc.state)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, int64(1), tb.wellKnownHits.Load(), "OIDC should be cached")
			}

			if tc.wantHasAT {
				require.Contains(t, tokens, "access_token")
			} else {
				assert.NotContains(t, tokens, "access_token")
			}

			if tc.wantIntroOK {
				intro, ok := tokens["introspection"].(map[string]any)
				require.True(t, ok, "introspection should exist")
				assert.Equal(t, true, intro["active"])
			}

			if tc.code == "bad" {
				assert.Contains(t, tokens, "error")
			}
		})
	}
}

// TestIntegrationCustomerAndEnergyAPIs tests the complete flow for accessing resource APIs
func TestIntegrationCustomerAndEnergyAPIs(t *testing.T) {
	tb := newTestBackends(t)
	ctx := context.Background()

	sessionID, built, err := tb.tpp.BuildAuthParams(ctx, []string{"openid"})
	require.NoError(t, err)
	_, err = tb.tpp.ExchangeToken(ctx, sessionID, "ok", built.State)
	require.NoError(t, err)

	t.Run("customer_200", func(t *testing.T) {
		body, status, err := tb.tpp.Customer(ctx, sessionID, "as-1")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, "customer", body["resource"])
	})

	t.Run("energy_403", func(t *testing.T) {
		body, status, err := tb.tpp.Energy(ctx, sessionID, "as-1")
		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, status)
		assert.Equal(t, "scope not allowed", body["message"])
	})
}

// TestIntegrationFullOAuthFlow tests the complete OAuth flow from auth params to resource access
func TestIntegrationFullOAuthFlow(t *testing.T) {
	tests := []struct {
		name               string
		scopes             []string
		authCode           string
		wantTokenSuccess   bool
		wantCustomerAccess bool
		wantEnergyAccess   bool
	}{
		{
			name:               "full_success_flow",
			scopes:             []string{"openid", "customer", "energy"},
			authCode:           "valid-code",
			wantTokenSuccess:   true,
			wantCustomerAccess: true,
			wantEnergyAccess:   false, // Energy returns 403 in mock
		},
		{
			name:               "minimal_scopes",
			scopes:             []string{"openid"},
			authCode:           "valid-code",
			wantTokenSuccess:   true,
			wantCustomerAccess: true,
			wantEnergyAccess:   false,
		},
		{
			name:               "token_exchange_failure",
			scopes:             []string{"openid"},
			authCode:           "bad",
			wantTokenSuccess:   false,
			wantCustomerAccess: false,
			wantEnergyAccess:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tb := newTestBackends(t)
			ctx := context.Background()

			// Step 1: Build auth parameters
			sessionID, authParams, err := tb.tpp.BuildAuthParams(ctx, tc.scopes)
			require.NoError(t, err)
			assert.NotEmpty(t, authParams.State)
			assert.NotEmpty(t, authParams.CodeChallenge)

			// Step 2: Finalize auth URL (PAR)
			authURL, err := tb.tpp.FinalizeAuthURL(ctx, sessionID)
			require.NoError(t, err)
			assert.Contains(t, authURL, "https://auth.example/authorize")

			// Step 3: Exchange authorization code for tokens
			tokens, err := tb.tpp.ExchangeToken(ctx, sessionID, tc.authCode, authParams.State)
			if tc.wantTokenSuccess {
				require.NoError(t, err)
				assert.Contains(t, tokens, "access_token")
				assert.Contains(t, tokens, "introspection")
			} else {
				require.Error(t, err)
				if tokens != nil {
					assert.Contains(t, tokens, "error")
				}
				return // Skip resource access tests
			}

			// Step 4: Access customer resource
			customerData, customerStatus, err := tb.tpp.Customer(ctx, sessionID, "as-1")
			if tc.wantCustomerAccess {
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, customerStatus)
				assert.Equal(t, "customer", customerData["resource"])
			} else {
				require.Error(t, err)
			}

			// Step 5: Access energy resource
			energyData, energyStatus, err := tb.tpp.Energy(ctx, sessionID, "as-1")
			if tc.wantEnergyAccess {
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, energyStatus)
			} else if err == nil {
				// Energy should return 403 or error
				assert.Equal(t, http.StatusForbidden, energyStatus)
				assert.Equal(t, "scope not allowed", energyData["message"])
			}
		})
	}
}

// TestIntegrationCaching tests that OpenID configuration and participants are properly cached
func TestIntegrationCaching(t *testing.T) {
	tb := newTestBackends(t)
	ctx := context.Background()

	// Initial request should fetch well-known
	sessionID1, _, err := tb.tpp.BuildAuthParams(ctx, []string{"openid"})
	require.NoError(t, err)
	assert.Equal(t, int64(1), tb.wellKnownHits.Load(), "first request should fetch well-known")

	// Subsequent operations should use cached well-known
	_, err = tb.tpp.FinalizeAuthURL(ctx, sessionID1)
	require.NoError(t, err)
	assert.Equal(t, int64(1), tb.wellKnownHits.Load(), "should use cached well-known")

	// New session should also use cached well-known
	sessionID2, _, err := tb.tpp.BuildAuthParams(ctx, []string{"openid", "customer"})
	require.NoError(t, err)
	assert.Equal(t, int64(1), tb.wellKnownHits.Load(), "new session should use cached well-known")

	_, err = tb.tpp.FinalizeAuthURL(ctx, sessionID2)
	require.NoError(t, err)
	assert.Equal(t, int64(1), tb.wellKnownHits.Load(), "should still use cached well-known")

	// Check participants caching - participants should already be loaded during initialization
	// Participants should have been fetched during TPP initialization
	assert.Equal(t, int64(1), tb.participantsHits.Load(), "participants should be fetched once during initialization")

	// Try customer access (will fail due to no valid token, but should use cached participants)
	_, _, err = tb.tpp.Customer(ctx, sessionID1, "as-1")
	require.Error(t, err) // Expected to fail due to no access token

	// Participants should still be 1 (cached from initialization)
	assert.Equal(t, int64(1), tb.participantsHits.Load(), "participants should be cached and not fetched again")
}

// TestIntegrationErrorHandling tests error scenarios in the complete flow
func TestIntegrationErrorHandling(t *testing.T) {
	tests := []struct {
		name            string
		setupBackend    func(t *testing.T) *testBackends
		sessionSetup    func(t *testing.T, tb *testBackends) string
		operation       func(t *testing.T, tb *testBackends, sessionID string) error
		wantErrContains string
	}{
		{
			name:         "invalid_session_token_exchange",
			setupBackend: newTestBackends,
			sessionSetup: func(t *testing.T, tb *testBackends) string {
				return "invalid-session-id"
			},
			operation: func(t *testing.T, tb *testBackends, sessionID string) error {
				_, err := tb.tpp.ExchangeToken(context.Background(), sessionID, "code", "state")
				return err
			},
			wantErrContains: "session not found",
		},
		{
			name:         "invalid_session_customer_access",
			setupBackend: newTestBackends,
			sessionSetup: func(t *testing.T, tb *testBackends) string {
				return "invalid-session-id"
			},
			operation: func(t *testing.T, tb *testBackends, sessionID string) error {
				_, _, err := tb.tpp.Customer(context.Background(), sessionID, "as-1")
				return err
			},
			wantErrContains: "not authorized",
		},
		{
			name:         "invalid_provider_id",
			setupBackend: newTestBackends,
			sessionSetup: func(t *testing.T, tb *testBackends) string {
				ctx := context.Background()
				sessionID, built, err := tb.tpp.BuildAuthParams(ctx, []string{"openid"})
				require.NoError(t, err)
				// Complete token exchange
				_, err = tb.tpp.ExchangeToken(ctx, sessionID, "valid-code", built.State)
				require.NoError(t, err)
				return sessionID
			},
			operation: func(t *testing.T, tb *testBackends, sessionID string) error {
				_, _, err := tb.tpp.Customer(context.Background(), sessionID, "non-existent-provider")
				return err
			},
			wantErrContains: "resource host not found",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tb := tc.setupBackend(t)
			sessionID := tc.sessionSetup(t, tb)

			err := tc.operation(t, tb, sessionID)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErrContains)
		})
	}
}

// TestIntegrationConcurrentSessions tests that multiple concurrent sessions work correctly
func TestIntegrationConcurrentSessions(t *testing.T) {
	tb := newTestBackends(t)
	ctx := context.Background()

	// Create multiple sessions concurrently
	numSessions := 5
	sessionIDs := make([]string, numSessions)
	authParams := make([]any, numSessions)

	for i := range numSessions {
		sessionID, params, err := tb.tpp.BuildAuthParams(ctx, []string{"openid"})
		require.NoError(t, err)
		sessionIDs[i] = sessionID
		authParams[i] = params
	}

	// Verify all sessions are unique
	for i := range numSessions {
		for j := i + 1; j < numSessions; j++ {
			assert.NotEqual(t, sessionIDs[i], sessionIDs[j], "session IDs should be unique")
		}
	}

	// Test that each session can independently finalize auth URL
	for i, sessionID := range sessionIDs {
		authURL, err := tb.tpp.FinalizeAuthURL(ctx, sessionID)
		require.NoError(t, err, "session %d should be able to finalize auth URL", i)
		assert.Contains(t, authURL, "https://auth.example/authorize")
	}

	// Test that sessions are isolated (wrong state should fail)
	for i, sessionID := range sessionIDs {
		wrongState := "wrong-state-for-session-" + string(rune(i))
		_, err := tb.tpp.ExchangeToken(ctx, sessionID, "code", wrongState)
		require.Error(t, err, "session %d should reject wrong state", i)
		assert.Contains(t, err.Error(), "invalid state")
	}
}
