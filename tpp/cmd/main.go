package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/raidiam/recco-mock-tpp/shared/logging"
	"github.com/raidiam/recco-mock-tpp/tpp"
)

func main() {
	logging.InitLogger()

	ctx := context.Background()
	slog.InfoContext(ctx, "starting TPP service")

	// Load configuration
	cfg, err := tpp.LoadConfig()
	if err != nil {
		slog.ErrorContext(ctx, "failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Setup clients and cache
	oauthClient, participantsCache, err := tpp.SetupClients(ctx, cfg)
	if err != nil {
		slog.ErrorContext(ctx, "failed to setup clients", "error", err)
		os.Exit(1)
	}

	// TPP service config
	tppCfg := tpp.Config{
		WellKnownURL:    cfg.WellKnownURL,
		ClientID:        cfg.ClientID,
		RedirectURI:     cfg.RedirectURI,
		ParticipantsURL: cfg.ParticipantsURL,
		OAuthClient:     oauthClient,
	}

	slog.InfoContext(ctx, "initializing TPP service and fetching OpenID configuration")
	tppSvc, err := tpp.NewWithContext(ctx, tppCfg, participantsCache)
	if err != nil {
		slog.ErrorContext(ctx, "failed to initialize TPP service", "error", err)
		os.Exit(1)
	}

	// HTTP server setup
	slog.InfoContext(ctx, "setting up HTTP server")
	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           tpp.Handler(cfg.FrontendOrigin, tppSvc),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	slog.InfoContext(ctx, "TPP service starting", "addr", cfg.ListenAddr, "https", true)
	if err := srv.ListenAndServeTLS(cfg.DevTLSCertFile, cfg.DevTLSKeyFile); err != nil {
		slog.ErrorContext(ctx, "TPP service stopped", "error", err)
		os.Exit(1)
	}
}
