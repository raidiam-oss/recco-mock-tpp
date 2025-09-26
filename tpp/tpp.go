package tpp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/raidiam/recco-mock-tpp/shared/cache"
	"github.com/raidiam/recco-mock-tpp/shared/client"
	"github.com/raidiam/recco-mock-tpp/shared/model"
)

type Config struct {
	WellKnownURL    string
	ClientID        string
	RedirectURI     string
	ParticipantsURL string
	OAuthClient     *client.OAuthClient
}

type TPP struct {
	cfg  Config
	oidc model.OpenIDConfiguration

	sessMu   sync.Mutex
	sessions map[string]*model.RuntimeSession

	Providers *cache.ParticipantCache
	provTTL   time.Duration
}

// NewWithContext creates a new TPP instance and immediately fetches the OpenID configuration
func NewWithContext(ctx context.Context, cfg Config, providers *cache.ParticipantCache) (*TPP, error) {
	tpp := &TPP{
		cfg:       cfg,
		sessions:  map[string]*model.RuntimeSession{},
		provTTL:   15 * time.Minute,
		Providers: providers,
	}

	// Fetch OpenID configuration once during initialization
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.WellKnownURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create well-known request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch well-known configuration: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("well-known configuration returned status %s", resp.Status)
	}

	var oidcConfig model.OpenIDConfiguration
	if err := json.NewDecoder(resp.Body).Decode(&oidcConfig); err != nil {
		return nil, fmt.Errorf("failed to decode well-known configuration: %w", err)
	}

	tpp.oidc = oidcConfig

	return tpp, nil
}
