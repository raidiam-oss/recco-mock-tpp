package tpp

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/raidiam/recco-mock-tpp/shared/cache"
	"github.com/raidiam/recco-mock-tpp/shared/client"
	"github.com/raidiam/recco-mock-tpp/shared/model"
	"github.com/raidiam/recco-mock-tpp/shared/signer"
	"github.com/raidiam/recco-mock-tpp/shared/tlsutil"
)

// LoadConfig loads and validates environment variables
func LoadConfig() (*model.Config, error) {
	ctx := context.Background()
	slog.InfoContext(ctx, "loading configuration from environment variables")

	requiredEnvVars := []string{
		"WELL_KNOWN_URL",
		"CLIENT_ID",
		"REDIRECT_URI",
		"PARTICIPANTS_URL",
		"MTLS_CERT_FILE",
		"MTLS_KEY_FILE",
		"MTLS_CA_FILE",
		"SIGNING_KEY_FILE",
		"SIGNING_KEY_ID",
		"DEV_TLS_CERT_FILE",
		"DEV_TLS_KEY_FILE",
	}

	for _, envVar := range requiredEnvVars {
		if val, ok := os.LookupEnv(envVar); !ok || val == "" {
			slog.Error("missing required environment variable", "key", envVar)
			return nil, fmt.Errorf("missing required environment variable: %s", envVar)
		}
	}

	// Load environment variables with defaults
	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":8080"
	}
	frontendOrigin := os.Getenv("APP_ORIGIN")
	if frontendOrigin == "" {
		frontendOrigin = "http://localhost:8080"
	}

	return &model.Config{
		WellKnownURL:    os.Getenv("WELL_KNOWN_URL"),
		ClientID:        os.Getenv("CLIENT_ID"),
		RedirectURI:     os.Getenv("REDIRECT_URI"),
		ParticipantsURL: os.Getenv("PARTICIPANTS_URL"),
		CertFile:        os.Getenv("MTLS_CERT_FILE"),
		KeyFile:         os.Getenv("MTLS_KEY_FILE"),
		CAFile:          os.Getenv("MTLS_CA_FILE"),
		SigningKeyFile:  os.Getenv("SIGNING_KEY_FILE"),
		SigningKeyID:    os.Getenv("SIGNING_KEY_ID"),
		DevTLSCertFile:  os.Getenv("DEV_TLS_CERT_FILE"),
		DevTLSKeyFile:   os.Getenv("DEV_TLS_KEY_FILE"),
		ListenAddr:      listenAddr,
		FrontendOrigin:  frontendOrigin,
	}, nil
}

// SetupClients initializes the clients and cache
func SetupClients(ctx context.Context, cfg *model.Config) (*client.OAuthClient, *cache.ParticipantCache, error) {
	// mTLS client config
	slog.InfoContext(ctx, "setting up mTLS client")
	mtlsClient, err := tlsutil.MTLSClient(cfg.CertFile, cfg.KeyFile, cfg.CAFile)
	if err != nil {
		slog.ErrorContext(ctx, "mtls client setup failed", "error", err)
		return nil, nil, err
	}

	// build signer
	slog.InfoContext(ctx, "loading JWT signer from signing key file", "file", cfg.SigningKeyFile, "kid", cfg.SigningKeyID)
	jwtSigner, err := signer.NewFromKeyFile(cfg.SigningKeyFile, cfg.SigningKeyID)
	if err != nil {
		slog.ErrorContext(ctx, "failed to init JWT signer", "error", err)
		return nil, nil, err
	}

	// OAuth client config
	oauthClient := client.New(client.Config{
		ClientID:     cfg.ClientID,
		WellKnownURL: cfg.WellKnownURL,
		MTLSClient:   mtlsClient,
		JWTSigner:    jwtSigner,
	})

	// initialise participants cache
	participantsCache, err := cache.NewParticipantCache(ctx, cfg.ParticipantsURL)
	if err != nil {
		slog.ErrorContext(ctx, "failed to initialise participants cache", "error", err)
		return nil, nil, err
	}

	updates := make(chan model.UpdateMessage)
	go cache.RefreshParticipantCache(context.Background(), participantsCache, 15*time.Minute, updates)

	go func() {
		for {
			updateMessage := <-updates
			slog.InfoContext(ctx, "attempted participants cache refresh", "updated", updateMessage.Updated, "message", updateMessage.Message)
		}
	}()

	return oauthClient, participantsCache, nil
}
