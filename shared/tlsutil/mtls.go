package tlsutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"
)

// MTLSClient creates an mTLS HTTP client with custom dialer configuration
func MTLSClient(certFile, keyFile, caFile string) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load key pair: %w", err)
	}

	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to get system cert pool: %w", err)
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read ca file: %w", err)
		}
		if ok := rootCAs.AppendCertsFromPEM(pem); !ok {
			return nil, fmt.Errorf("failed to append CA certs")
		}
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      rootCAs,
			MinVersion:   tls.VersionTLS13,
		},
	}

	// Use custom dialer
	baseTLS := tr.TLSClientConfig
	tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
			port = "443"
		}

		cfg := baseTLS
		if cfg == nil {
			cfg = &tls.Config{MinVersion: tls.VersionTLS13}
		}
		clone := cfg.Clone()
		clone.ServerName = host

		nd := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
		td := &tls.Dialer{NetDialer: nd, Config: clone}

		dc, err := td.DialContext(ctx, network, net.JoinHostPort(host, port))
		if err != nil {
			slog.ErrorContext(ctx, "mtls dial failed", "host", host, "port", port, "error", err)
		}
		return dc, err
	}

	return &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
	}, nil
}
