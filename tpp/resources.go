package tpp

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/raidiam/recco-mock-tpp/shared/model"
)

// Customer fetches customer data from the specified provider
func (t *TPP) Customer(ctx context.Context, sessionID, providerID string) (map[string]any, int, error) {
	host, err := t.resolveResourceHost(ctx, providerID, model.APITypeCustomer)
	if err != nil {
		return nil, 0, err
	}
	return t.getJSON(ctx, host+"/recco/customer/v1/customer", sessionID)
}

// Energy fetches energy data from the specified provider
func (t *TPP) Energy(ctx context.Context, sessionID, providerID string) (map[string]any, int, error) {
	host, err := t.resolveResourceHost(ctx, providerID, model.APITypeEnergy)
	if err != nil {
		return nil, 0, err
	}
	return t.getJSON(ctx, host+"/recco/energy/v1/energy", sessionID)
}

// resolveResourceHost finds the appropriate resource host for a given provider and API type
func (t *TPP) resolveResourceHost(ctx context.Context, authServerID string, kind model.APIType) (string, error) {
	authServers := t.Providers.AuthServers()

	for _, as := range authServers {
		if as.ID != authServerID {
			continue
		}
		for _, r := range as.Resources {
			if r.APIType == kind && len(r.DiscoveryEndpoints) > 0 {
				u, err := url.Parse(r.DiscoveryEndpoints[0].Endpoint)
				if err != nil {
					return "", fmt.Errorf("parse endpoint: %w", err)
				}

				host := "https://" + u.Host
				slog.InfoContext(ctx, "resource host resolved",
					"auth_server_id", authServerID,
					"api_type", string(kind),
					"host", host,
				)
				return host, nil
			}
		}
	}
	return "", fmt.Errorf("resource host not found for %s", authServerID)
}

// getJSON makes an authenticated JSON request to the specified URI
func (t *TPP) getJSON(ctx context.Context, uri, sessionID string) (map[string]any, int, error) {
	sess := t.getSession(sessionID)
	if sess == nil || sess.AccessToken == "" {
		return nil, 0, fmt.Errorf("not authorized")
	}

	return t.cfg.OAuthClient.GetJSON(ctx, uri, sess.AccessToken)
}
