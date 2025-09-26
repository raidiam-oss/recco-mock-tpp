package tpp_test

import (
	"context"
	"os"
	"testing"

	"github.com/raidiam/recco-mock-tpp/shared/model"
	"github.com/raidiam/recco-mock-tpp/tpp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name            string
		setupEnv        func(t *testing.T)
		wantErr         bool
		wantErrContains string
		validateConfig  func(t *testing.T, cfg *model.Config)
	}{
		{
			name: "all_required_env_vars_set",
			setupEnv: func(t *testing.T) {
				setTestEnvVars(t, map[string]string{
					"WELL_KNOWN_URL":    "https://auth.example/.well-known/openid-configuration",
					"CLIENT_ID":         "test-client-123",
					"REDIRECT_URI":      "https://app.example/callback",
					"PARTICIPANTS_URL":  "https://directory.example/participants",
					"MTLS_CERT_FILE":    "/path/to/cert.pem",
					"MTLS_KEY_FILE":     "/path/to/key.pem",
					"MTLS_CA_FILE":      "/path/to/ca.pem",
					"SIGNING_KEY_FILE":  "/path/to/signing.pem",
					"SIGNING_KEY_ID":    "signing-key-1",
					"DEV_TLS_CERT_FILE": "/path/to/dev-cert.pem",
					"DEV_TLS_KEY_FILE":  "/path/to/dev-key.pem",
					"LISTEN_ADDR":       ":9090",
					"APP_ORIGIN":        "https://frontend.example",
				})
			},
			wantErr: false,
			validateConfig: func(t *testing.T, cfg *model.Config) {
				assert.Equal(t, "https://auth.example/.well-known/openid-configuration", cfg.WellKnownURL)
				assert.Equal(t, "test-client-123", cfg.ClientID)
				assert.Equal(t, "https://app.example/callback", cfg.RedirectURI)
				assert.Equal(t, "https://directory.example/participants", cfg.ParticipantsURL)
				assert.Equal(t, "/path/to/cert.pem", cfg.CertFile)
				assert.Equal(t, "/path/to/key.pem", cfg.KeyFile)
				assert.Equal(t, "/path/to/ca.pem", cfg.CAFile)
				assert.Equal(t, "/path/to/signing.pem", cfg.SigningKeyFile)
				assert.Equal(t, "signing-key-1", cfg.SigningKeyID)
				assert.Equal(t, "/path/to/dev-cert.pem", cfg.DevTLSCertFile)
				assert.Equal(t, "/path/to/dev-key.pem", cfg.DevTLSKeyFile)
				assert.Equal(t, ":9090", cfg.ListenAddr)
				assert.Equal(t, "https://frontend.example", cfg.FrontendOrigin)
			},
		},
		{
			name: "default_values_applied",
			setupEnv: func(t *testing.T) {
				setTestEnvVars(t, map[string]string{
					"WELL_KNOWN_URL":    "https://auth.example/.well-known/openid-configuration",
					"CLIENT_ID":         "test-client",
					"REDIRECT_URI":      "https://app.example/callback",
					"PARTICIPANTS_URL":  "https://directory.example/participants",
					"MTLS_CERT_FILE":    "/path/to/cert.pem",
					"MTLS_KEY_FILE":     "/path/to/key.pem",
					"MTLS_CA_FILE":      "/path/to/ca.pem",
					"SIGNING_KEY_FILE":  "/path/to/signing.pem",
					"SIGNING_KEY_ID":    "signing-key-1",
					"DEV_TLS_CERT_FILE": "/path/to/dev-cert.pem",
					"DEV_TLS_KEY_FILE":  "/path/to/dev-key.pem",
					// LISTEN_ADDR and APP_ORIGIN not set - should use defaults
				})
			},
			wantErr: false,
			validateConfig: func(t *testing.T, cfg *model.Config) {
				assert.Equal(t, ":8080", cfg.ListenAddr)
				assert.Equal(t, "http://localhost:8080", cfg.FrontendOrigin)
			},
		},
		{
			name: "empty_optional_env_vars_use_defaults",
			setupEnv: func(t *testing.T) {
				setTestEnvVars(t, map[string]string{
					"WELL_KNOWN_URL":    "https://auth.example/.well-known/openid-configuration",
					"CLIENT_ID":         "test-client",
					"REDIRECT_URI":      "https://app.example/callback",
					"PARTICIPANTS_URL":  "https://directory.example/participants",
					"MTLS_CERT_FILE":    "/path/to/cert.pem",
					"MTLS_KEY_FILE":     "/path/to/key.pem",
					"MTLS_CA_FILE":      "/path/to/ca.pem",
					"SIGNING_KEY_FILE":  "/path/to/signing.pem",
					"SIGNING_KEY_ID":    "signing-key-1",
					"DEV_TLS_CERT_FILE": "/path/to/dev-cert.pem",
					"DEV_TLS_KEY_FILE":  "/path/to/dev-key.pem",
					"LISTEN_ADDR":       "", // Empty string should use default
					"APP_ORIGIN":        "", // Empty string should use default
				})
			},
			wantErr: false,
			validateConfig: func(t *testing.T, cfg *model.Config) {
				assert.Equal(t, ":8080", cfg.ListenAddr)
				assert.Equal(t, "http://localhost:8080", cfg.FrontendOrigin)
			},
		},
		{
			name: "missing_well_known_url",
			setupEnv: func(t *testing.T) {
				setTestEnvVars(t, map[string]string{
					// "WELL_KNOWN_URL" missing
					"CLIENT_ID":         "test-client",
					"REDIRECT_URI":      "https://app.example/callback",
					"PARTICIPANTS_URL":  "https://directory.example/participants",
					"MTLS_CERT_FILE":    "/path/to/cert.pem",
					"MTLS_KEY_FILE":     "/path/to/key.pem",
					"MTLS_CA_FILE":      "/path/to/ca.pem",
					"SIGNING_KEY_FILE":  "/path/to/signing.pem",
					"SIGNING_KEY_ID":    "signing-key-1",
					"DEV_TLS_CERT_FILE": "/path/to/dev-cert.pem",
					"DEV_TLS_KEY_FILE":  "/path/to/dev-key.pem",
				})
			},
			wantErr:         true,
			wantErrContains: "missing required environment variable: WELL_KNOWN_URL",
		},
		{
			name: "missing_client_id",
			setupEnv: func(t *testing.T) {
				setTestEnvVars(t, map[string]string{
					"WELL_KNOWN_URL": "https://auth.example/.well-known/openid-configuration",
					// "CLIENT_ID" missing
					"REDIRECT_URI":      "https://app.example/callback",
					"PARTICIPANTS_URL":  "https://directory.example/participants",
					"MTLS_CERT_FILE":    "/path/to/cert.pem",
					"MTLS_KEY_FILE":     "/path/to/key.pem",
					"MTLS_CA_FILE":      "/path/to/ca.pem",
					"SIGNING_KEY_FILE":  "/path/to/signing.pem",
					"SIGNING_KEY_ID":    "signing-key-1",
					"DEV_TLS_CERT_FILE": "/path/to/dev-cert.pem",
					"DEV_TLS_KEY_FILE":  "/path/to/dev-key.pem",
				})
			},
			wantErr:         true,
			wantErrContains: "missing required environment variable: CLIENT_ID",
		},
		{
			name: "empty_required_env_var",
			setupEnv: func(t *testing.T) {
				setTestEnvVars(t, map[string]string{
					"WELL_KNOWN_URL":    "https://auth.example/.well-known/openid-configuration",
					"CLIENT_ID":         "", // Empty string should be treated as missing
					"REDIRECT_URI":      "https://app.example/callback",
					"PARTICIPANTS_URL":  "https://directory.example/participants",
					"MTLS_CERT_FILE":    "/path/to/cert.pem",
					"MTLS_KEY_FILE":     "/path/to/key.pem",
					"MTLS_CA_FILE":      "/path/to/ca.pem",
					"SIGNING_KEY_FILE":  "/path/to/signing.pem",
					"SIGNING_KEY_ID":    "signing-key-1",
					"DEV_TLS_CERT_FILE": "/path/to/dev-cert.pem",
					"DEV_TLS_KEY_FILE":  "/path/to/dev-key.pem",
				})
			},
			wantErr:         true,
			wantErrContains: "missing required environment variable: CLIENT_ID",
		},
		{
			name: "missing_multiple_required_vars",
			setupEnv: func(t *testing.T) {
				setTestEnvVars(t, map[string]string{
					"WELL_KNOWN_URL": "https://auth.example/.well-known/openid-configuration",
					"CLIENT_ID":      "test-client",
					// Multiple required vars missing
				})
			},
			wantErr:         true,
			wantErrContains: "missing required environment variable:",
		},
		{
			name: "all_mtls_files_missing",
			setupEnv: func(t *testing.T) {
				setTestEnvVars(t, map[string]string{
					"WELL_KNOWN_URL":   "https://auth.example/.well-known/openid-configuration",
					"CLIENT_ID":        "test-client",
					"REDIRECT_URI":     "https://app.example/callback",
					"PARTICIPANTS_URL": "https://directory.example/participants",
					// All mTLS files missing
					"SIGNING_KEY_FILE":  "/path/to/signing.pem",
					"SIGNING_KEY_ID":    "signing-key-1",
					"DEV_TLS_CERT_FILE": "/path/to/dev-cert.pem",
					"DEV_TLS_KEY_FILE":  "/path/to/dev-key.pem",
				})
			},
			wantErr:         true,
			wantErrContains: "missing required environment variable:",
		},
		{
			name: "custom_listen_addr_formats",
			setupEnv: func(t *testing.T) {
				setTestEnvVars(t, map[string]string{
					"WELL_KNOWN_URL":    "https://auth.example/.well-known/openid-configuration",
					"CLIENT_ID":         "test-client",
					"REDIRECT_URI":      "https://app.example/callback",
					"PARTICIPANTS_URL":  "https://directory.example/participants",
					"MTLS_CERT_FILE":    "/path/to/cert.pem",
					"MTLS_KEY_FILE":     "/path/to/key.pem",
					"MTLS_CA_FILE":      "/path/to/ca.pem",
					"SIGNING_KEY_FILE":  "/path/to/signing.pem",
					"SIGNING_KEY_ID":    "signing-key-1",
					"DEV_TLS_CERT_FILE": "/path/to/dev-cert.pem",
					"DEV_TLS_KEY_FILE":  "/path/to/dev-key.pem",
					"LISTEN_ADDR":       "localhost:3000",
					"APP_ORIGIN":        "https://custom.frontend.com",
				})
			},
			wantErr: false,
			validateConfig: func(t *testing.T, cfg *model.Config) {
				assert.Equal(t, "localhost:3000", cfg.ListenAddr)
				assert.Equal(t, "https://custom.frontend.com", cfg.FrontendOrigin)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Clean environment before each test
			clearTestEnvVars(t)

			// Setup test environment
			if tc.setupEnv != nil {
				tc.setupEnv(t)
			}

			// Test LoadConfig
			cfg, err := tpp.LoadConfig()

			if tc.wantErr {
				require.Error(t, err)
				if tc.wantErrContains != "" {
					assert.Contains(t, err.Error(), tc.wantErrContains)
				}
				assert.Nil(t, cfg)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cfg)
				if tc.validateConfig != nil {
					tc.validateConfig(t, cfg)
				}
			}
		})
	}
}

func TestSetupClients(t *testing.T) {
	tests := []struct {
		name            string
		config          *model.Config
		wantErr         bool
		wantErrContains string
	}{
		{
			name: "invalid_cert_file",
			config: &model.Config{
				WellKnownURL:    "https://auth.example/.well-known/openid-configuration",
				ClientID:        "test-client",
				ParticipantsURL: "https://directory.example/participants",
				CertFile:        "/nonexistent/cert.pem",
				KeyFile:         "/nonexistent/key.pem",
				CAFile:          "/nonexistent/ca.pem",
				SigningKeyFile:  "/nonexistent/signing.pem",
				SigningKeyID:    "test-key-1",
			},
			wantErr:         true,
			wantErrContains: "failed to load key pair",
		},
		{
			name: "invalid_signing_key_file",
			config: &model.Config{
				WellKnownURL:    "https://auth.example/.well-known/openid-configuration",
				ClientID:        "test-client",
				ParticipantsURL: "https://directory.example/participants",
				CertFile:        "/dev/null", // Use /dev/null as a "valid" file that won't work as cert
				KeyFile:         "/dev/null",
				CAFile:          "/dev/null",
				SigningKeyFile:  "/nonexistent/signing.pem",
				SigningKeyID:    "test-key-1",
			},
			wantErr:         true,
			wantErrContains: "failed to find any PEM data",
		},
		{
			name: "invalid_participants_url",
			config: &model.Config{
				WellKnownURL:    "https://auth.example/.well-known/openid-configuration",
				ClientID:        "test-client",
				ParticipantsURL: "invalid-url-format",
				CertFile:        "/dev/null",
				KeyFile:         "/dev/null",
				CAFile:          "/dev/null",
				SigningKeyFile:  "/dev/null",
				SigningKeyID:    "test-key-1",
			},
			wantErr:         true,
			wantErrContains: "failed to find any PEM data",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			oauthClient, participantsCache, err := tpp.SetupClients(ctx, tc.config)

			if tc.wantErr {
				require.Error(t, err)
				if tc.wantErrContains != "" {
					assert.Contains(t, err.Error(), tc.wantErrContains)
				}
				assert.Nil(t, oauthClient)
				assert.Nil(t, participantsCache)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, oauthClient)
				assert.NotNil(t, participantsCache)
			}
		})
	}
}

// Test helper functions

func setTestEnvVars(t *testing.T, envVars map[string]string) {
	t.Helper()
	for key, value := range envVars {
		err := os.Setenv(key, value)
		require.NoError(t, err)
		t.Cleanup(func() {
			os.Unsetenv(key)
		})
	}
}

func clearTestEnvVars(t *testing.T) {
	t.Helper()
	requiredEnvVars := []string{
		"WELL_KNOWN_URL", "CLIENT_ID", "REDIRECT_URI", "PARTICIPANTS_URL",
		"MTLS_CERT_FILE", "MTLS_KEY_FILE", "MTLS_CA_FILE",
		"SIGNING_KEY_FILE", "SIGNING_KEY_ID",
		"DEV_TLS_CERT_FILE", "DEV_TLS_KEY_FILE",
		"LISTEN_ADDR", "APP_ORIGIN",
	}
	for _, envVar := range requiredEnvVars {
		os.Unsetenv(envVar)
	}
}
