package tpp

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"

	"github.com/raidiam/recco-mock-tpp/shared/model"
	"github.com/rs/cors"
	"github.com/unrolled/secure"
)

const cookieSessionID = "session_id"

// Handler creates the HTTP handler for the TPP service with static pages and auth flow
func Handler(host string, tppService *TPP) http.Handler {
	secureMiddleware := secure.New(secure.Options{
		FrameDeny:             true,
		ContentTypeNosniff:    true,
		BrowserXssFilter:      true,
		ContentSecurityPolicy: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';",
	})

	corsMiddleware := cors.New(cors.Options{
		AllowedOrigins:   []string{host},
		AllowCredentials: true,
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodHead},
	})

	mux := http.NewServeMux()

	// static pages + assets
	mux.Handle("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		render(w, "index.html", nil)
	}))
	mux.Handle("GET /index", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		render(w, "index.html", nil)
	}))
	mux.Handle("GET /api", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		render(w, "api.html", nil)
	}))
	staticDir := filepath.Join("web", "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir))))

	// flow endpoints
	mux.Handle("POST /auth/build", buildAuthHandler(tppService))
	mux.Handle("POST /auth/finalize", finalizeAuthHandler(tppService))
	mux.Handle("POST /auth/token", tokenHandler(tppService))

	// providers
	mux.Handle("GET /providers", providersHandler(tppService))

	// data APIs (proxy to API service)
	mux.Handle("GET /api/customer", customerHandler(tppService))
	mux.Handle("GET /api/energy", energyHandler(tppService))

	return corsMiddleware.Handler(secureMiddleware.Handler(mux))
}

// Auth flow handlers

func buildAuthHandler(tppService *TPP) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.InfoContext(r.Context(), "building auth params")
		var body model.BuildAuthRequest
		err := json.NewDecoder(r.Body).Decode(&body)
		if err != nil {
			slog.ErrorContext(r.Context(), "failed to decode request body", "error", err)
			renderError(w, err, http.StatusInternalServerError)
			return
		}

		sessionID, out, err := tppService.BuildAuthParams(r.Context(), body.Scopes)
		if err != nil {
			slog.ErrorContext(r.Context(), "build auth params failed", "error", err)
			renderError(w, err, http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     cookieSessionID,
			Value:    sessionID,
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			Path:     "/",
			MaxAge:   3600,
		})

		if err := writeJSON(w, model.BuildAuthResponse{
			ResponseType:        out.ResponseType,
			ClientID:            out.ClientID,
			RedirectURI:         out.RedirectURI,
			Scope:               out.Scope,
			CodeChallengeMethod: "S256",
			CodeChallenge:       out.CodeChallenge,
			State:               out.State,
			Nonce:               out.Nonce,
		}, http.StatusOK); err != nil {
			slog.ErrorContext(r.Context(), "failed to write JSON response", "error", err)
		}
	})
}

func finalizeAuthHandler(tppService *TPP) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.InfoContext(r.Context(), "finalizing auth url (PAR)")
		cookie, err := r.Cookie(cookieSessionID)
		if err != nil {
			slog.ErrorContext(r.Context(), "cookie not found", "error", err)
			renderError(w, fmt.Errorf("missing session"), http.StatusUnauthorized)
			return
		}
		url, err := tppService.FinalizeAuthURL(r.Context(), cookie.Value)
		if err != nil {
			slog.ErrorContext(r.Context(), "finalize auth failed", "error", err)
			renderError(w, err, http.StatusBadRequest)
			return
		}
		if err := writeJSON(w, model.FinalizeAuthResponse{AuthURL: url}, http.StatusOK); err != nil {
			slog.ErrorContext(r.Context(), "failed to write JSON response", "error", err)
		}
	})
}

func tokenHandler(tppService *TPP) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.InfoContext(r.Context(), "starting token exchange")
		var body model.TokenExchangeRequest
		err := json.NewDecoder(r.Body).Decode(&body)
		if err != nil {
			slog.ErrorContext(r.Context(), "failed to decode request body", "error", err)
			renderError(w, err, http.StatusInternalServerError)
			return
		}

		cookie, err := r.Cookie(cookieSessionID)
		if err != nil {
			slog.ErrorContext(r.Context(), "cookie not found", "error", err)
			renderError(w, fmt.Errorf("missing session"), http.StatusUnauthorized)
			return
		}

		tokens, err := tppService.ExchangeToken(r.Context(), cookie.Value, body.Code, body.State)
		if err != nil {
			slog.ErrorContext(r.Context(), "token exchange failed", "error", err)
			renderError(w, err, http.StatusBadRequest)
			return
		}
		if err := writeJSON(w, tokens, http.StatusOK); err != nil {
			slog.ErrorContext(r.Context(), "failed to write JSON response", "error", err)
		}
	})
}

// Provider and resource handlers

func providersHandler(tppService *TPP) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.InfoContext(r.Context(), "getting list of auth servers")
		list := tppService.Providers.AuthServers()
		if err := writeJSON(w, list, http.StatusOK); err != nil {
			slog.ErrorContext(r.Context(), "failed to write JSON response", "error", err)
		}
	})
}

func customerHandler(tppService *TPP) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.InfoContext(r.Context(), "fetching customer endpoint")
		cookie, err := r.Cookie(cookieSessionID)
		if err != nil {
			slog.ErrorContext(r.Context(), "cookie not found", "error", err)
			renderError(w, fmt.Errorf("missing session"), http.StatusUnauthorized)
			return
		}
		providerID := r.URL.Query().Get("provider_id")
		data, status, err := tppService.Customer(r.Context(), cookie.Value, providerID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error while fetching customer data", "error", err)
			renderError(w, err, http.StatusBadGateway)
			return
		}
		if err := writeJSON(w, data, status); err != nil {
			slog.ErrorContext(r.Context(), "failed to write JSON response", "error", err)
		}
	})
}

func energyHandler(tppService *TPP) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.InfoContext(r.Context(), "fetching energy endpoint")
		cookie, err := r.Cookie(cookieSessionID)
		if err != nil {
			slog.ErrorContext(r.Context(), "cookie not found", "error", err)
			renderError(w, fmt.Errorf("missing session"), http.StatusUnauthorized)
			return
		}
		providerID := r.URL.Query().Get("provider_id")
		data, status, err := tppService.Energy(r.Context(), cookie.Value, providerID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error while fetching energy data", "error", err)
			renderError(w, err, http.StatusBadGateway)
			return
		}
		if err := writeJSON(w, data, status); err != nil {
			slog.ErrorContext(r.Context(), "failed to write JSON response", "error", err)
		}
	})
}

// Utility functions

func writeJSON(w http.ResponseWriter, data any, status int) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(data)
}

func renderError(w http.ResponseWriter, err error, status int) {
	if jsonErr := writeJSON(w, map[string]string{"error": err.Error()}, status); jsonErr != nil {
		slog.Error("failed to write JSON error response", "error", jsonErr, "original_error", err)
	}
}
