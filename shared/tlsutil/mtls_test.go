package tlsutil_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/raidiam/recco-mock-tpp/shared/tlsutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMTLSClient_Success(t *testing.T) {
	t.Parallel()

	caCert, caKey, caPEM := makeCA(t)

	srvCertPEM, srvKeyPEM := makeLeafCert(t, caCert, caKey, false, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	srvTLSCert, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	require.NoError(t, err, "server keypair")

	cliCertPEM, cliKeyPEM := makeLeafCert(t, caCert, caKey, true, nil, nil)

	td := t.TempDir()
	cliCertFile := filepath.Join(td, "client.pem")
	cliKeyFile := filepath.Join(td, "client.key")
	caFile := filepath.Join(td, "ca.pem")
	require.NoError(t, os.WriteFile(cliCertFile, cliCertPEM, 0o600))
	require.NoError(t, os.WriteFile(cliKeyFile, cliKeyPEM, 0o600))
	require.NoError(t, os.WriteFile(caFile, caPEM, 0o600))

	h := http.NewServeMux()
	h.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("pong"))
		require.NoError(t, err)
	})
	ts := httptest.NewUnstartedServer(h)
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{srvTLSCert},
		ClientCAs:    poolFromPEM(t, caPEM),
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	ts.StartTLS()
	defer ts.Close()

	client, err := tlsutil.MTLSClient(cliCertFile, cliKeyFile, caFile)
	require.NoError(t, err, "MTLSClient")

	tr, ok := client.Transport.(*http.Transport)
	require.True(t, ok, "transport type should be *http.Transport")
	assert.Equal(t, uint16(tls.VersionTLS13), tr.TLSClientConfig.MinVersion, "TLS min version")

	resp, err := client.Get(ts.URL + "/ping")
	require.NoError(t, err, "GET /ping")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestMTLSClient_Errors(t *testing.T) {
	t.Parallel()

	t.Run("bad_keypair", func(t *testing.T) {
		t.Parallel()

		td := t.TempDir()
		cert := filepath.Join(td, "c.pem")
		key := filepath.Join(td, "k.pem")
		require.NoError(t, os.WriteFile(cert, []byte("not a cert"), 0o600))
		require.NoError(t, os.WriteFile(key, []byte("not a key"), 0o600))

		_, err := tlsutil.MTLSClient(cert, key, "")
		require.Error(t, err)
	})

	t.Run("bad_ca_file", func(t *testing.T) {
		t.Parallel()
		caCert, caKey, _ := makeCA(t)
		cliCertPEM, cliKeyPEM := makeLeafCert(t, caCert, caKey, true, nil, nil)

		td := t.TempDir()
		cert := filepath.Join(td, "client.pem")
		key := filepath.Join(td, "client.key")
		ca := filepath.Join(td, "ca.pem")
		require.NoError(t, os.WriteFile(cert, cliCertPEM, 0o600))
		require.NoError(t, os.WriteFile(key, cliKeyPEM, 0o600))
		require.NoError(t, os.WriteFile(ca, []byte(" definitely not PEM "), 0o600))

		_, err := tlsutil.MTLSClient(cert, key, ca)
		require.Error(t, err)
	})
}

// helpers
func makeCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, priv, caPEM
}

func makeLeafCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, client bool, dns []string, ips []net.IP) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: map[bool]string{true: "client", false: "server"}[client]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	if client {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &priv.PublicKey, caKey)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	b, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	return
}

func poolFromPEM(t *testing.T, pemBytes []byte) *x509.CertPool {
	t.Helper()
	p := x509.NewCertPool()
	ok := p.AppendCertsFromPEM(pemBytes)
	require.True(t, ok, "AppendCertsFromPEM failed")
	return p
}
