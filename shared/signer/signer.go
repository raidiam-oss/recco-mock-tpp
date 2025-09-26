package signer

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/go-jose/go-jose/v4"
)

// NewFromKeyFile creates a JWT signer from a PEM key file
func NewFromKeyFile(pemPath, kid string) (jose.Signer, error) {
	b, err := os.ReadFile(pemPath)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}

	var (
		block *pem.Block
		rest  = b
		key   any
	)
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "RSA PRIVATE KEY":
			k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse pkcs1: %w", err)
			}
			key = k
		case "PRIVATE KEY":
			kAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse pkcs8: %w", err)
			}
			key = kAny
		}
		if key != nil {
			break
		}
	}
	if key == nil {
		return nil, fmt.Errorf("no supported private key found in %s", pemPath)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}
	if rsaKey.N.BitLen() < 2048 {
		return nil, fmt.Errorf("key size too small: %d bits (need >= 2048)", rsaKey.N.BitLen())
	}

	opts := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.PS256, Key: rsaKey}, opts)
	if err != nil {
		return nil, fmt.Errorf("new signer: %w", err)
	}

	return signer, nil
}
