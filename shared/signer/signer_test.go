package signer_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/raidiam/recco-mock-tpp/shared/signer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFromKeyFile(t *testing.T) {
	tests := []struct {
		name            string
		setupKeyFile    func(t *testing.T) string
		kid             string
		wantErr         bool
		wantErrContains string
		validateSigner  func(t *testing.T, s jose.Signer)
	}{
		{
			name: "valid_rsa_pkcs1_key",
			setupKeyFile: func(t *testing.T) string {
				return createTestKeyFile(t, "RSA PRIVATE KEY", generateRSAKey(t, 2048), x509.MarshalPKCS1PrivateKey)
			},
			kid:     "test-key-1",
			wantErr: false,
			validateSigner: func(t *testing.T, s jose.Signer) {
				assert.NotNil(t, s)
				// Test that we can sign something
				signed, err := s.Sign([]byte(`{"test": "payload"}`))
				require.NoError(t, err)
				assert.NotEmpty(t, signed.FullSerialize())
			},
		},
		{
			name: "valid_rsa_pkcs8_key",
			setupKeyFile: func(t *testing.T) string {
				return createTestKeyFile(t, "PRIVATE KEY", generateRSAKey(t, 2048), func(key *rsa.PrivateKey) []byte {
					bytes, err := x509.MarshalPKCS8PrivateKey(key)
					require.NoError(t, err)
					return bytes
				})
			},
			kid:     "test-key-2",
			wantErr: false,
			validateSigner: func(t *testing.T, s jose.Signer) {
				assert.NotNil(t, s)
			},
		},
		{
			name: "multiple_keys_in_file",
			setupKeyFile: func(t *testing.T) string {
				var buf bytes.Buffer

				// Write first block (certificate - should be ignored)
				certBlock := &pem.Block{
					Type:  "CERTIFICATE",
					Bytes: []byte("dummy certificate data that will be ignored"),
				}
				err := pem.Encode(&buf, certBlock)
				require.NoError(t, err)

				// Write second block (valid RSA private key)
				key := generateRSAKey(t, 2048)
				keyBytes := x509.MarshalPKCS1PrivateKey(key)
				keyBlock := &pem.Block{
					Type:  "RSA PRIVATE KEY",
					Bytes: keyBytes,
				}
				err = pem.Encode(&buf, keyBlock)
				require.NoError(t, err)

				tmpFile := filepath.Join(t.TempDir(), "multi-key.pem")
				err = os.WriteFile(tmpFile, buf.Bytes(), 0600)
				require.NoError(t, err)

				return tmpFile
			},
			kid:     "test-key-multi",
			wantErr: false,
			validateSigner: func(t *testing.T, s jose.Signer) {
				assert.NotNil(t, s)
			},
		},
		{
			name: "key_size_too_small",
			setupKeyFile: func(t *testing.T) string {
				return createTestKeyFile(t, "RSA PRIVATE KEY", generateRSAKey(t, 1024), x509.MarshalPKCS1PrivateKey)
			},
			kid:             "test-key-small",
			wantErr:         true,
			wantErrContains: "key size too small: 1024 bits (need >= 2048)",
		},
		{
			name: "file_not_found",
			setupKeyFile: func(t *testing.T) string {
				return "/nonexistent/path/key.pem"
			},
			kid:             "test-key-missing",
			wantErr:         true,
			wantErrContains: "read key:",
		},
		{
			name: "invalid_pem_format",
			setupKeyFile: func(t *testing.T) string {
				tmpFile := filepath.Join(t.TempDir(), "invalid.pem")
				err := os.WriteFile(tmpFile, []byte("not a valid pem file"), 0600)
				require.NoError(t, err)
				return tmpFile
			},
			kid:             "test-key-invalid",
			wantErr:         true,
			wantErrContains: "no supported private key found",
		},
		{
			name: "invalid_pkcs1_key",
			setupKeyFile: func(t *testing.T) string {
				tmpFile := filepath.Join(t.TempDir(), "invalid-pkcs1.pem")
				f, err := os.Create(tmpFile)
				require.NoError(t, err)
				defer f.Close()

				block := &pem.Block{
					Type:  "RSA PRIVATE KEY",
					Bytes: []byte("invalid key data"),
				}
				err = pem.Encode(f, block)
				require.NoError(t, err)

				return tmpFile
			},
			kid:             "test-key-invalid-pkcs1",
			wantErr:         true,
			wantErrContains: "parse pkcs1:",
		},
		{
			name: "invalid_pkcs8_key",
			setupKeyFile: func(t *testing.T) string {
				tmpFile := filepath.Join(t.TempDir(), "invalid-pkcs8.pem")
				f, err := os.Create(tmpFile)
				require.NoError(t, err)
				defer f.Close()

				block := &pem.Block{
					Type:  "PRIVATE KEY",
					Bytes: []byte("invalid key data"),
				}
				err = pem.Encode(f, block)
				require.NoError(t, err)

				return tmpFile
			},
			kid:             "test-key-invalid-pkcs8",
			wantErr:         true,
			wantErrContains: "parse pkcs8:",
		},
		{
			name: "empty_file",
			setupKeyFile: func(t *testing.T) string {
				tmpFile := filepath.Join(t.TempDir(), "empty.pem")
				err := os.WriteFile(tmpFile, []byte(""), 0600)
				require.NoError(t, err)
				return tmpFile
			},
			kid:             "test-key-empty",
			wantErr:         true,
			wantErrContains: "no supported private key found",
		},
		{
			name: "unsupported_key_type",
			setupKeyFile: func(t *testing.T) string {
				tmpFile := filepath.Join(t.TempDir(), "unsupported.pem")
				f, err := os.Create(tmpFile)
				require.NoError(t, err)
				defer f.Close()

				block := &pem.Block{
					Type:  "EC PRIVATE KEY",
					Bytes: []byte("ec key data"),
				}
				err = pem.Encode(f, block)
				require.NoError(t, err)

				return tmpFile
			},
			kid:             "test-key-ec",
			wantErr:         true,
			wantErrContains: "no supported private key found",
		},
		{
			name: "empty_kid",
			setupKeyFile: func(t *testing.T) string {
				return createTestKeyFile(t, "RSA PRIVATE KEY", generateRSAKey(t, 2048), x509.MarshalPKCS1PrivateKey)
			},
			kid:     "",
			wantErr: false,
			validateSigner: func(t *testing.T, s jose.Signer) {
				assert.NotNil(t, s)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keyFile := tc.setupKeyFile(t)

			signer, err := signer.NewFromKeyFile(keyFile, tc.kid)

			if tc.wantErr {
				require.Error(t, err)
				if tc.wantErrContains != "" {
					assert.Contains(t, err.Error(), tc.wantErrContains)
				}
				assert.Nil(t, signer)
			} else {
				require.NoError(t, err)
				require.NotNil(t, signer)
				if tc.validateSigner != nil {
					tc.validateSigner(t, signer)
				}
			}
		})
	}
}

func TestNewFromKeyFile_SignerConfiguration(t *testing.T) {
	tests := []struct {
		name        string
		kid         string
		keySize     int
		validateJWT func(t *testing.T, signer jose.Signer, kid string)
	}{
		{
			name:    "signer_can_sign_data",
			kid:     "test-kid-123",
			keySize: 2048,
			validateJWT: func(t *testing.T, signer jose.Signer, kid string) {
				signed, err := signer.Sign([]byte(`{"test": "data"}`))
				require.NoError(t, err)

				// Verify we can serialize the JWT
				serialized := signed.FullSerialize()
				assert.NotEmpty(t, serialized)

				// Verify we have at least one signature
				require.True(t, len(signed.Signatures) > 0)
			},
		},
		{
			name:    "signer_with_empty_kid",
			kid:     "",
			keySize: 2048,
			validateJWT: func(t *testing.T, signer jose.Signer, kid string) {
				signed, err := signer.Sign([]byte(`{"test": "data"}`))
				require.NoError(t, err)

				serialized := signed.FullSerialize()
				assert.NotEmpty(t, serialized)
			},
		},
		{
			name:    "large_key_size_4096",
			kid:     "large-key",
			keySize: 4096,
			validateJWT: func(t *testing.T, signer jose.Signer, kid string) {
				signed, err := signer.Sign([]byte(`{"test": "data"}`))
				require.NoError(t, err)
				assert.NotEmpty(t, signed.FullSerialize())
			},
		},
		{
			name:    "different_payload_sizes",
			kid:     "test-payload",
			keySize: 2048,
			validateJWT: func(t *testing.T, signer jose.Signer, kid string) {
				// Test with small payload
				signed1, err := signer.Sign([]byte(`{"a": "b"}`))
				require.NoError(t, err)
				assert.NotEmpty(t, signed1.FullSerialize())

				// Test with larger payload
				largePayload := `{"data": "` + string(make([]byte, 1000)) + `"}`
				signed2, err := signer.Sign([]byte(largePayload))
				require.NoError(t, err)
				assert.NotEmpty(t, signed2.FullSerialize())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keyFile := createTestKeyFile(t, "RSA PRIVATE KEY", generateRSAKey(t, tc.keySize), x509.MarshalPKCS1PrivateKey)

			signer, err := signer.NewFromKeyFile(keyFile, tc.kid)
			require.NoError(t, err)
			require.NotNil(t, signer)

			if tc.validateJWT != nil {
				tc.validateJWT(t, signer, tc.kid)
			}
		})
	}
}

func TestNewFromKeyFile_ErrorCases(t *testing.T) {
	tests := []struct {
		name          string
		setupFile     func(t *testing.T) string
		kid           string
		expectedError string
	}{
		{
			name: "permission_denied",
			setupFile: func(t *testing.T) string {
				keyFile := createTestKeyFile(t, "RSA PRIVATE KEY", generateRSAKey(t, 2048), x509.MarshalPKCS1PrivateKey)
				// Remove read permissions
				err := os.Chmod(keyFile, 0000)
				require.NoError(t, err)
				t.Cleanup(func() {
					err := os.Chmod(keyFile, 0600) // Restore permissions for cleanup
					require.NoError(t, err)
				})
				return keyFile
			},
			kid:           "test-key",
			expectedError: "read key:",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keyFile := tc.setupFile(t)

			signer, err := signer.NewFromKeyFile(keyFile, tc.kid)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectedError)
			assert.Nil(t, signer)
		})
	}
}

// Helper functions

func generateRSAKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	return key
}

func createTestKeyFile(t *testing.T, blockType string, key *rsa.PrivateKey, marshalFunc func(*rsa.PrivateKey) []byte) string {
	t.Helper()

	tmpFile := filepath.Join(t.TempDir(), "test-key.pem")
	f, err := os.Create(tmpFile)
	require.NoError(t, err)
	defer f.Close()

	keyBytes := marshalFunc(key)
	block := &pem.Block{
		Type:  blockType,
		Bytes: keyBytes,
	}

	err = pem.Encode(f, block)
	require.NoError(t, err)

	return tmpFile
}
