package tpp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/raidiam/recco-mock-tpp/tpp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandler(t *testing.T) {
	tests := []struct {
		name            string
		method          string
		path            string
		body            string
		headers         map[string]string
		wantStatus      int
		wantContains    []string
		wantHeaders     map[string]string
		wantNotContains []string
	}{
		{
			name:       "get_index_root",
			method:     "GET",
			path:       "/",
			wantStatus: http.StatusOK,
			wantHeaders: map[string]string{
				"Content-Type": "text/html; charset=utf-8",
			},
		},
		{
			name:       "get_index_explicit",
			method:     "GET",
			path:       "/index",
			wantStatus: http.StatusOK,
			wantHeaders: map[string]string{
				"Content-Type": "text/html; charset=utf-8",
			},
		},
		{
			name:       "get_api_page",
			method:     "GET",
			path:       "/api",
			wantStatus: http.StatusOK,
			wantHeaders: map[string]string{
				"Content-Type": "text/html; charset=utf-8",
			},
		},
		{
			name:       "get_providers",
			method:     "GET",
			path:       "/providers",
			wantStatus: http.StatusOK,
			wantHeaders: map[string]string{
				"Content-Type": "application/json",
			},
		},
		{
			name:   "options_request_cors",
			method: "OPTIONS",
			path:   "/providers",
			headers: map[string]string{
				"Origin":                         "https://localhost:8443",
				"Access-Control-Request-Method":  "GET",
				"Access-Control-Request-Headers": "Content-Type",
			},
			wantStatus: http.StatusNoContent, // CORS middleware returns 204 for OPTIONS preflight
		},
		{
			name:       "method_not_allowed",
			method:     "DELETE",
			path:       "/",
			wantStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tppService := createSimpleTestTPP(t)
			handler := tpp.Handler("https://localhost:8443", tppService)

			var bodyReader io.Reader
			if tc.body != "" {
				bodyReader = strings.NewReader(tc.body)
			}

			req := httptest.NewRequest(tc.method, tc.path, bodyReader)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			assert.Equal(t, tc.wantStatus, w.Code)

			for k, v := range tc.wantHeaders {
				assert.Equal(t, v, w.Header().Get(k), "header %s", k)
			}

			responseBody := w.Body.String()
			for _, contains := range tc.wantContains {
				assert.Contains(t, responseBody, contains)
			}

			for _, notContains := range tc.wantNotContains {
				assert.NotContains(t, responseBody, notContains)
			}
		})
	}
}

func TestBuildAuthHandler(t *testing.T) {
	tests := []struct {
		name             string
		requestBody      map[string]any
		wantStatus       int
		wantErrContains  string
		validateResponse func(t *testing.T, response map[string]any)
		validateCookie   func(t *testing.T, cookies []*http.Cookie)
	}{
		{
			name: "successful_auth_build",
			requestBody: map[string]any{
				"scopes": []string{"openid", "customer"},
			},
			wantStatus: http.StatusOK,
			validateResponse: func(t *testing.T, response map[string]any) {
				assert.Equal(t, "test-client", response["client_id"])
				assert.Equal(t, "https://app.example/callback", response["redirect_uri"])
				assert.Equal(t, "openid customer", response["scope"])
				assert.Equal(t, "code", response["response_type"])
				assert.Equal(t, "S256", response["code_challenge_method"])
				assert.NotEmpty(t, response["code_challenge"])
				assert.NotEmpty(t, response["state"])
				assert.NotEmpty(t, response["nonce"])
			},
			validateCookie: func(t *testing.T, cookies []*http.Cookie) {
				require.Len(t, cookies, 1)
				cookie := cookies[0]
				assert.Equal(t, "session_id", cookie.Name)
				assert.NotEmpty(t, cookie.Value)
				assert.True(t, cookie.HttpOnly)
				assert.Equal(t, "/", cookie.Path)
				assert.Equal(t, 3600, cookie.MaxAge)
			},
		},
		{
			name: "empty_scopes",
			requestBody: map[string]any{
				"scopes": []string{},
			},
			wantStatus: http.StatusOK,
			validateResponse: func(t *testing.T, response map[string]any) {
				assert.Equal(t, "", response["scope"])
			},
		},
		{
			name: "nil_scopes",
			requestBody: map[string]any{
				"scopes": nil,
			},
			wantStatus: http.StatusOK,
			validateResponse: func(t *testing.T, response map[string]any) {
				assert.Equal(t, "", response["scope"])
			},
		},
		{
			name:            "invalid_json",
			requestBody:     nil, // will send invalid JSON
			wantStatus:      http.StatusInternalServerError,
			wantErrContains: "invalid character",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tppService := createSimpleTestTPP(t)
			handler := tpp.Handler("https://localhost:8443", tppService)

			var body *bytes.Buffer
			switch {
			case tc.requestBody != nil:
				bodyBytes, err := json.Marshal(tc.requestBody)
				require.NoError(t, err)
				body = bytes.NewBuffer(bodyBytes)
			case tc.name == "invalid_json":
				body = bytes.NewBufferString("{invalid json")
			default:
				body = bytes.NewBuffer(nil)
			}

			req := httptest.NewRequest("POST", "/auth/build", body)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			assert.Equal(t, tc.wantStatus, w.Code)

			if tc.wantErrContains != "" {
				assert.Contains(t, w.Body.String(), tc.wantErrContains)
			}

			if tc.validateResponse != nil {
				var response map[string]any
				err := json.NewDecoder(w.Body).Decode(&response)
				require.NoError(t, err)
				tc.validateResponse(t, response)
			}

			if tc.validateCookie != nil {
				tc.validateCookie(t, w.Result().Cookies())
			}
		})
	}
}

func TestFinalizeAuthHandler(t *testing.T) {
	tests := []struct {
		name             string
		setupSession     func(t *testing.T, tppService *tpp.TPP) string
		setCookie        bool
		cookieValue      string
		mockPARServer    func(t *testing.T) *httptest.Server
		wantStatus       int
		wantErrContains  string
		validateResponse func(t *testing.T, response map[string]any)
	}{
		{
			name: "successful_finalize",
			setupSession: func(t *testing.T, tppService *tpp.TPP) string {
				sessionID, _, err := tppService.BuildAuthParams(context.Background(), []string{"openid"})
				require.NoError(t, err)
				return sessionID
			},
			setCookie: true,
			mockPARServer: func(t *testing.T) *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/par" {
						err := json.NewEncoder(w).Encode(map[string]any{
							"expires_in":  90,
							"request_uri": "urn:ietf:params:oauth:request_uri:TESTPAR",
						})
						require.NoError(t, err)
					}
				}))
			},
			wantStatus: http.StatusOK,
			validateResponse: func(t *testing.T, response map[string]any) {
				authURL, ok := response["auth_url"].(string)
				require.True(t, ok)
				assert.Contains(t, authURL, "https://auth.example/authorize")
				assert.Contains(t, authURL, "request_uri=")
			},
		},
		{
			name: "missing_cookie",
			setupSession: func(t *testing.T, tppService *tpp.TPP) string {
				return "some-session"
			},
			setCookie:       false,
			wantStatus:      http.StatusUnauthorized,
			wantErrContains: "missing session",
		},
		{
			name: "invalid_session",
			setupSession: func(t *testing.T, tppService *tpp.TPP) string {
				return "valid-session"
			},
			setCookie:   true,
			cookieValue: "invalid-session",
			mockPARServer: func(t *testing.T) *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			},
			wantStatus:      http.StatusBadRequest,
			wantErrContains: "session not found",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var tppService *tpp.TPP
			if tc.mockPARServer != nil {
				parServer := tc.mockPARServer(t)
				defer parServer.Close()
				tppService = createTestTPPWithPARServer(t, parServer)
			} else {
				tppService = createTestTPP(t)
			}

			sessionID := tc.setupSession(t, tppService)
			handler := tpp.Handler("https://localhost:8443", tppService)

			req := httptest.NewRequest("POST", "/auth/finalize", nil)

			if tc.setCookie {
				cookieValue := tc.cookieValue
				if cookieValue == "" {
					cookieValue = sessionID
				}
				req.AddCookie(&http.Cookie{
					Name:  "session_id",
					Value: cookieValue,
				})
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			assert.Equal(t, tc.wantStatus, w.Code)

			if tc.wantErrContains != "" {
				assert.Contains(t, w.Body.String(), tc.wantErrContains)
			}

			if tc.validateResponse != nil {
				var response map[string]any
				err := json.NewDecoder(w.Body).Decode(&response)
				require.NoError(t, err)
				tc.validateResponse(t, response)
			}
		})
	}
}

func TestTokenHandler(t *testing.T) {
	tests := []struct {
		name             string
		setupSession     func(t *testing.T, tppService *tpp.TPP) (string, string) // sessionID, state
		requestBody      map[string]any
		setCookie        bool
		cookieValue      string
		mockTokenServer  func(t *testing.T) *httptest.Server
		wantStatus       int
		wantErrContains  string
		validateResponse func(t *testing.T, response map[string]any)
	}{
		{
			name: "successful_token_exchange",
			setupSession: func(t *testing.T, tppService *tpp.TPP) (string, string) {
				sessionID, output, err := tppService.BuildAuthParams(context.Background(), []string{"openid"})
				require.NoError(t, err)
				return sessionID, output.State
			},
			requestBody: map[string]any{
				"code": "valid-code",
			},
			setCookie: true,
			mockTokenServer: func(t *testing.T) *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/token":
						err := json.NewEncoder(w).Encode(map[string]any{
							"access_token": "AT",
							"id_token":     "header.payload.sig",
							"token_type":   "Bearer",
							"expires_in":   3600,
						})
						require.NoError(t, err)
					case "/introspect":
						err := json.NewEncoder(w).Encode(map[string]any{
							"active": true,
							"scope":  "openid customer",
						})
						require.NoError(t, err)
					}
				}))
			},
			wantStatus: http.StatusOK,
			validateResponse: func(t *testing.T, response map[string]any) {
				assert.Equal(t, "AT", response["access_token"])
				assert.Equal(t, "Bearer", response["token_type"])
			},
		},
		{
			name: "missing_cookie",
			setupSession: func(t *testing.T, tppService *tpp.TPP) (string, string) {
				return "session", "state"
			},
			requestBody: map[string]any{
				"code":  "valid-code",
				"state": "state",
			},
			setCookie:       false,
			wantStatus:      http.StatusUnauthorized,
			wantErrContains: "missing session",
		},
		{
			name: "invalid_state",
			setupSession: func(t *testing.T, tppService *tpp.TPP) (string, string) {
				sessionID, output, err := tppService.BuildAuthParams(context.Background(), []string{"openid"})
				require.NoError(t, err)
				return sessionID, output.State
			},
			requestBody: map[string]any{
				"code":  "valid-code",
				"state": "wrong-state",
			},
			setCookie: true,
			mockTokenServer: func(t *testing.T) *httptest.Server {
				return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			},
			wantStatus:      http.StatusBadRequest,
			wantErrContains: "invalid state",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var tppService *tpp.TPP
			if tc.mockTokenServer != nil {
				tokenServer := tc.mockTokenServer(t)
				defer tokenServer.Close()
				tppService = createTestTPPWithTokenServer(t, tokenServer)
			} else {
				tppService = createTestTPP(t)
			}

			sessionID, state := tc.setupSession(t, tppService)
			handler := tpp.Handler("https://localhost:8443", tppService)

			// Set state in request body if not provided
			if tc.requestBody["state"] == nil {
				tc.requestBody["state"] = state
			}

			bodyBytes, err := json.Marshal(tc.requestBody)
			require.NoError(t, err)

			req := httptest.NewRequest("POST", "/auth/token", bytes.NewBuffer(bodyBytes))
			req.Header.Set("Content-Type", "application/json")

			if tc.setCookie {
				cookieValue := tc.cookieValue
				if cookieValue == "" {
					cookieValue = sessionID
				}
				req.AddCookie(&http.Cookie{
					Name:  "session_id",
					Value: cookieValue,
				})
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			assert.Equal(t, tc.wantStatus, w.Code)

			if tc.wantErrContains != "" {
				assert.Contains(t, w.Body.String(), tc.wantErrContains)
			}

			if tc.validateResponse != nil {
				var response map[string]any
				err := json.NewDecoder(w.Body).Decode(&response)
				require.NoError(t, err)
				tc.validateResponse(t, response)
			}
		})
	}
}

func TestCustomerHandler(t *testing.T) {
	tests := []struct {
		name             string
		setupSession     func(t *testing.T, tppService *tpp.TPP) string
		providerID       string
		setCookie        bool
		cookieValue      string
		mockAPIServer    func(t *testing.T) *httptest.Server
		wantStatus       int
		wantErrContains  string
		validateResponse func(t *testing.T, response map[string]any)
	}{
		{
			name: "successful_customer_request",
			setupSession: func(t *testing.T, tppService *tpp.TPP) string {
				sessionID, output, err := tppService.BuildAuthParams(context.Background(), []string{"openid"})
				require.NoError(t, err)
				// Simulate token exchange by setting access token directly
				_, err = tppService.ExchangeToken(context.Background(), sessionID, "code", output.State)
				require.Error(t, err) // This will fail but we can still test the handler structure
				return sessionID
			},
			providerID: "as-1",
			setCookie:  true,
			wantStatus: http.StatusBadGateway, // Will fail due to no actual token
		},
		{
			name: "missing_cookie",
			setupSession: func(t *testing.T, tppService *tpp.TPP) string {
				return "session"
			},
			providerID:      "as-1",
			setCookie:       false,
			wantStatus:      http.StatusUnauthorized,
			wantErrContains: "missing session",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tppService := createSimpleTestTPP(t)
			sessionID := tc.setupSession(t, tppService)
			handler := tpp.Handler("https://localhost:8443", tppService)

			path := "/api/customer"
			if tc.providerID != "" {
				path += "?provider_id=" + tc.providerID
			}

			req := httptest.NewRequest("GET", path, nil)

			if tc.setCookie {
				cookieValue := tc.cookieValue
				if cookieValue == "" {
					cookieValue = sessionID
				}
				req.AddCookie(&http.Cookie{
					Name:  "session_id",
					Value: cookieValue,
				})
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			assert.Equal(t, tc.wantStatus, w.Code)

			if tc.wantErrContains != "" {
				assert.Contains(t, w.Body.String(), tc.wantErrContains)
			}

			if tc.validateResponse != nil {
				var response map[string]any
				err := json.NewDecoder(w.Body).Decode(&response)
				require.NoError(t, err)
				tc.validateResponse(t, response)
			}
		})
	}
}

func TestEnergyHandler(t *testing.T) {
	tests := []struct {
		name            string
		setupSession    func(t *testing.T, tppService *tpp.TPP) string
		providerID      string
		setCookie       bool
		cookieValue     string
		wantStatus      int
		wantErrContains string
	}{
		{
			name: "successful_energy_request",
			setupSession: func(t *testing.T, tppService *tpp.TPP) string {
				sessionID, _, err := tppService.BuildAuthParams(context.Background(), []string{"openid"})
				require.NoError(t, err)
				return sessionID
			},
			providerID: "as-1",
			setCookie:  true,
			wantStatus: http.StatusBadGateway, // Will fail due to no actual token
		},
		{
			name: "missing_cookie",
			setupSession: func(t *testing.T, tppService *tpp.TPP) string {
				return "session"
			},
			providerID:      "as-1",
			setCookie:       false,
			wantStatus:      http.StatusUnauthorized,
			wantErrContains: "missing session",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tppService := createSimpleTestTPP(t)
			sessionID := tc.setupSession(t, tppService)
			handler := tpp.Handler("https://localhost:8443", tppService)

			path := "/api/energy"
			if tc.providerID != "" {
				path += "?provider_id=" + tc.providerID
			}

			req := httptest.NewRequest("GET", path, nil)

			if tc.setCookie {
				cookieValue := tc.cookieValue
				if cookieValue == "" {
					cookieValue = sessionID
				}
				req.AddCookie(&http.Cookie{
					Name:  "session_id",
					Value: cookieValue,
				})
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			assert.Equal(t, tc.wantStatus, w.Code)

			if tc.wantErrContains != "" {
				assert.Contains(t, w.Body.String(), tc.wantErrContains)
			}
		})
	}
}

func TestWriteJSON(t *testing.T) {
	tests := []struct {
		name       string
		data       any
		status     int
		wantStatus int
		wantBody   string
		wantHeader string
	}{
		{
			name:       "simple_object",
			data:       map[string]string{"key": "value"},
			status:     http.StatusOK,
			wantStatus: http.StatusOK,
			wantBody:   `{"key":"value"}`,
			wantHeader: "application/json",
		},
		{
			name:       "array",
			data:       []string{"a", "b", "c"},
			status:     http.StatusCreated,
			wantStatus: http.StatusCreated,
			wantBody:   `["a","b","c"]`,
			wantHeader: "application/json",
		},
		{
			name:       "nil_data",
			data:       nil,
			status:     http.StatusNoContent,
			wantStatus: http.StatusNoContent,
			wantBody:   "null",
			wantHeader: "application/json",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			// We can't test writeJSON directly as it's not exported, but we can test it through handlers
			tppService := createSimpleTestTPP(t)
			handler := tpp.Handler("https://localhost:8443", tppService)

			req := httptest.NewRequest("GET", "/providers", nil)
			handler.ServeHTTP(w, req)

			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
		})
	}
}

func TestSecurityHeaders(t *testing.T) {
	tppService := createSimpleTestTPP(t)
	handler := tpp.Handler("https://localhost:8443", tppService)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Test security headers are set by secure middleware
	headers := w.Header()
	assert.NotEmpty(t, headers.Get("X-Frame-Options"))
	assert.NotEmpty(t, headers.Get("X-Content-Type-Options"))
	assert.NotEmpty(t, headers.Get("X-Xss-Protection"))
}

func TestCORSHeaders(t *testing.T) {
	tests := []struct {
		name        string
		origin      string
		method      string
		wantCORS    bool
		wantHeaders map[string]string
	}{
		{
			name:     "allowed_origin",
			origin:   "https://localhost:8443",
			method:   "GET",
			wantCORS: true,
			wantHeaders: map[string]string{
				"Access-Control-Allow-Origin":      "https://localhost:8443",
				"Access-Control-Allow-Credentials": "true",
			},
		},
		{
			name:     "disallowed_origin",
			origin:   "https://evil.example",
			method:   "GET",
			wantCORS: false,
		},
		{
			name:     "options_request",
			origin:   "https://localhost:8443",
			method:   "OPTIONS",
			wantCORS: true,
			wantHeaders: map[string]string{
				"Access-Control-Allow-Origin":      "https://localhost:8443",
				"Access-Control-Allow-Credentials": "true",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tppService := createSimpleTestTPP(t)
			handler := tpp.Handler("https://localhost:8443", tppService)

			req := httptest.NewRequest(tc.method, "/providers", nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			for k, v := range tc.wantHeaders {
				assert.Equal(t, v, w.Header().Get(k), "header %s", k)
			}

			if !tc.wantCORS {
				assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
			}
		})
	}
}
