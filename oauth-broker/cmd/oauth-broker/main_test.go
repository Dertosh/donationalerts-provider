package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func testConfig() config {
	return config{clientID: "12345", clientSecret: "test-secret"}
}

func TestLoadConfig(t *testing.T) {
	t.Run("requires credentials", func(t *testing.T) {
		_, err := loadConfig(func(string) string { return "" })
		if err == nil {
			t.Fatal("expected missing credentials to be rejected")
		}
		if strings.Contains(err.Error(), "test-secret") {
			t.Fatal("configuration error must not contain credentials")
		}
	})

	t.Run("rejects malformed client ID", func(t *testing.T) {
		values := map[string]string{
			"DONATIONALERTS_CLIENT_ID":     "12x45",
			"DONATIONALERTS_CLIENT_SECRET": "test-secret",
		}
		_, err := loadConfig(func(key string) string { return values[key] })
		if err == nil {
			t.Fatal("expected malformed client ID to be rejected")
		}
	})

	t.Run("accepts valid credentials", func(t *testing.T) {
		values := map[string]string{
			"DONATIONALERTS_CLIENT_ID":     "12345",
			"DONATIONALERTS_CLIENT_SECRET": "test-secret",
		}
		got, err := loadConfig(func(key string) string { return values[key] })
		if err != nil {
			t.Fatalf("loadConfig returned an error: %v", err)
		}
		if got.clientID != "12345" || got.clientSecret != "test-secret" {
			t.Fatal("loaded configuration did not match test values")
		}
	})
}

func TestHealthAndPublicConfig(t *testing.T) {
	handler := newBroker(testConfig(), nil, tokenEndpoint).handler()

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK || !strings.Contains(health.Body.String(), `"status":"ok"`) {
		t.Fatalf("unexpected health response: %d %s", health.Code, health.Body.String())
	}

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/oauth/config", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"clientId":"12345"`) {
		t.Fatalf("unexpected config response: %d %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), testConfig().clientSecret) {
		t.Fatal("public config must not expose the application secret")
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("OAuth configuration must not be cached")
	}
}

func TestTokenExchangeUsesServerCredentialsAndReturnsOnlyTokenFields(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Errorf("upstream method = %s, want POST", request.Method)
		}
		if got := request.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Errorf("upstream Content-Type = %q", got)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read upstream request: %v", err)
			return
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			t.Errorf("parse upstream request: %v", err)
			return
		}
		if form.Get("client_id") != "12345" || form.Get("client_secret") != "test-secret" {
			t.Error("broker did not use its configured application credentials")
		}
		if form.Get("code") != "one-time-code" ||
			form.Get("redirect_uri") != defaultRedirectURI ||
			form.Get("grant_type") != "authorization_code" {
			t.Errorf("unexpected upstream OAuth form: %#v", form)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"access_token":"access-value","refresh_token":"refresh-value","token_type":"Bearer","expires_in":3600,"internal":"not-forwarded"}`)
	}))
	defer upstream.Close()

	handler := newBroker(testConfig(), upstream.Client(), upstream.URL).handler()
	body := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"one-time-code"},
		"redirect_uri": {defaultRedirectURI},
	}.Encode()
	request := httptest.NewRequest(http.MethodPost, "/v1/oauth/token", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("token exchange returned %d: %s", response.Code, response.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if result["access_token"] != "access-value" || result["refresh_token"] != "refresh-value" ||
		result["token_type"] != "Bearer" || result["expires_in"] != float64(3600) {
		t.Fatalf("unexpected token response: %#v", result)
	}
	if _, exists := result["internal"]; exists {
		t.Fatal("broker forwarded an unexpected upstream response field")
	}
	if strings.Contains(response.Body.String(), testConfig().clientSecret) {
		t.Fatal("token response exposed the application secret")
	}
}

func TestTokenEndpointRejectsInvalidRequestsWithoutCallingUpstream(t *testing.T) {
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamCalled = true
	}))
	defer upstream.Close()
	handler := newBroker(testConfig(), upstream.Client(), upstream.URL).handler()

	tests := []struct {
		name        string
		method      string
		path        string
		contentType string
		body        string
		wantStatus  int
	}{
		{name: "wrong method", method: http.MethodGet, wantStatus: http.StatusMethodNotAllowed},
		{name: "wrong content type", method: http.MethodPost, contentType: "application/json", body: `{}`, wantStatus: http.StatusUnsupportedMediaType},
		{name: "query string", method: http.MethodPost, path: "/v1/oauth/token?refresh_token=abc", contentType: "application/x-www-form-urlencoded", body: "grant_type=refresh_token&refresh_token=abc", wantStatus: http.StatusBadRequest},
		{name: "unsupported grant", method: http.MethodPost, contentType: "application/x-www-form-urlencoded", body: "grant_type=password", wantStatus: http.StatusBadRequest},
		{name: "unregistered redirect", method: http.MethodPost, contentType: "application/x-www-form-urlencoded", body: "grant_type=authorization_code&code=abc&redirect_uri=https%3A%2F%2Fevil.example%2Fcallback", wantStatus: http.StatusBadRequest},
		{name: "duplicate code", method: http.MethodPost, contentType: "application/x-www-form-urlencoded", body: "grant_type=authorization_code&code=one&code=two&redirect_uri=" + url.QueryEscape(defaultRedirectURI), wantStatus: http.StatusBadRequest},
		{name: "grant-specific extra field", method: http.MethodPost, contentType: "application/x-www-form-urlencoded", body: "grant_type=authorization_code&code=abc&redirect_uri=" + url.QueryEscape(defaultRedirectURI) + "&refresh_token=extra", wantStatus: http.StatusBadRequest},
		{name: "unexpected credential field", method: http.MethodPost, contentType: "application/x-www-form-urlencoded", body: "grant_type=refresh_token&refresh_token=abc&client_secret=attacker", wantStatus: http.StatusBadRequest},
		{name: "invalid scope", method: http.MethodPost, contentType: "application/x-www-form-urlencoded", body: "grant_type=refresh_token&refresh_token=abc&scope=admin", wantStatus: http.StatusBadRequest},
		{name: "oversized body", method: http.MethodPost, contentType: "application/x-www-form-urlencoded", body: strings.Repeat("x", maxRequestBytes+1), wantStatus: http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			upstreamCalled = false
			path := test.path
			if path == "" {
				path = "/v1/oauth/token"
			}
			request := httptest.NewRequest(test.method, path, strings.NewReader(test.body))
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.wantStatus, response.Body.String())
			}
			if upstreamCalled {
				t.Fatal("invalid request reached the upstream token endpoint")
			}
		})
	}
}

func TestUpstreamErrorDoesNotEchoSensitiveDetails(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(writer, `{"error":"invalid_grant","error_description":"refresh-secret-value"}`)
	}))
	defer upstream.Close()

	handler := newBroker(testConfig(), upstream.Client(), upstream.URL).handler()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"refresh-secret-value"}}
	request := httptest.NewRequest(http.MethodPost, "/v1/oauth/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"error":"invalid_grant"`) {
		t.Fatalf("unexpected sanitized OAuth error: %d %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "refresh-secret-value") {
		t.Fatal("OAuth error response echoed a token or upstream description")
	}
}

func TestTokenEndpointReturnsServiceUnavailableWhenConcurrencyLimitIsReached(t *testing.T) {
	b := newBroker(testConfig(), nil, tokenEndpoint)
	for range maxConcurrentCalls {
		b.upstreamGate <- struct{}{}
	}
	handler := b.handler()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"refresh-value"}}
	request := httptest.NewRequest(http.MethodPost, "/v1/oauth/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}
