package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	defaultRedirectURI = "http://127.0.0.1:4041/oauth/callback"
	tokenEndpoint      = "https://www.donationalerts.com/oauth/token"
	maxRequestBytes    = 16 * 1024
	maxResponseBytes   = 64 * 1024
	maxConcurrentCalls = 16
)

type config struct {
	clientID     string
	clientSecret string
}

type broker struct {
	config       config
	client       *http.Client
	tokenURL     string
	upstreamGate chan struct{}
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

func loadConfig(getenv func(string) string) (config, error) {
	clientID := strings.TrimSpace(getenv("DONATIONALERTS_CLIENT_ID"))
	clientSecret := getenv("DONATIONALERTS_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		return config{}, errors.New("DONATIONALERTS_CLIENT_ID and DONATIONALERTS_CLIENT_SECRET must be configured")
	}
	if len(clientID) > 64 || !isDigits(clientID) {
		return config{}, errors.New("DONATIONALERTS_CLIENT_ID must contain only digits and be at most 64 characters")
	}
	if len(clientSecret) > 4096 || strings.TrimSpace(clientSecret) == "" {
		return config{}, errors.New("DONATIONALERTS_CLIENT_SECRET is invalid")
	}
	return config{clientID: clientID, clientSecret: clientSecret}, nil
}

func isDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func newBroker(configuration config, client *http.Client, upstreamURL string) *broker {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &broker{
		config:       configuration,
		client:       client,
		tokenURL:     upstreamURL,
		upstreamGate: make(chan struct{}, maxConcurrentCalls),
	}
}

func (b *broker) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", b.handleHealth)
	mux.HandleFunc("/v1/oauth/config", b.handleConfig)
	mux.HandleFunc("/v1/oauth/token", b.handleToken)
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		header := writer.Header()
		header.Set("Cache-Control", "no-store")
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("Referrer-Policy", "no-referrer")
		header.Set("Strict-Transport-Security", "max-age=31536000")
		next.ServeHTTP(writer, request)
	})
}

func (b *broker) handleHealth(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (b *broker) handleConfig(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"clientId": b.config.clientID})
}

func (b *broker) handleToken(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if request.URL.RawQuery != "" {
		writeError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	contentType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || contentType != "application/x-www-form-urlencoded" {
		writeError(writer, http.StatusUnsupportedMediaType, "form_urlencoded_required")
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxRequestBytes+1))
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	if len(body) > maxRequestBytes {
		writeError(writer, http.StatusRequestEntityTooLarge, "request_too_large")
		return
	}
	fields, err := url.ParseQuery(string(body))
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	for key, values := range fields {
		if len(values) != 1 || !allowedField(key) {
			writeError(writer, http.StatusBadRequest, "invalid_request")
			return
		}
	}
	grantType := fields.Get("grant_type")
	upstreamForm := url.Values{
		"grant_type":    {grantType},
		"client_id":     {b.config.clientID},
		"client_secret": {b.config.clientSecret},
	}
	switch grantType {
	case "authorization_code":
		code := fields.Get("code")
		redirectURI := fields.Get("redirect_uri")
		if !hasOnlyFields(fields, "grant_type", "code", "redirect_uri") ||
			!validOpaqueValue(code, 4096) || redirectURI != defaultRedirectURI {
			writeError(writer, http.StatusBadRequest, "invalid_request")
			return
		}
		upstreamForm.Set("code", code)
		upstreamForm.Set("redirect_uri", defaultRedirectURI)
	case "refresh_token":
		refreshToken := fields.Get("refresh_token")
		if !hasOnlyFields(fields, "grant_type", "refresh_token", "scope") ||
			!validOpaqueValue(refreshToken, 4096) {
			writeError(writer, http.StatusBadRequest, "invalid_request")
			return
		}
		upstreamForm.Set("refresh_token", refreshToken)
		if scope := fields.Get("scope"); scope != "" {
			if len(scope) > 512 || !validScopeList(scope) {
				writeError(writer, http.StatusBadRequest, "invalid_scope")
				return
			}
			upstreamForm.Set("scope", scope)
		}
	default:
		writeError(writer, http.StatusBadRequest, "unsupported_grant_type")
		return
	}

	select {
	case b.upstreamGate <- struct{}{}:
		defer func() { <-b.upstreamGate }()
	case <-request.Context().Done():
		return
	default:
		writeError(writer, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	b.exchangeToken(writer, request, upstreamForm)
}

func allowedField(key string) bool {
	switch key {
	case "grant_type", "code", "redirect_uri", "refresh_token", "scope":
		return true
	default:
		return false
	}
}

func hasOnlyFields(fields url.Values, allowed ...string) bool {
	for key := range fields {
		found := false
		for _, candidate := range allowed {
			if key == candidate {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func validOpaqueValue(value string, maxLength int) bool {
	if value == "" || len(value) > maxLength {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character == 0x7f {
			return false
		}
	}
	return true
}

func validScopeList(value string) bool {
	allowed := map[string]bool{
		"oauth-user-show":          true,
		"oauth-donation-index":     true,
		"oauth-donation-subscribe": true,
		"oauth-goal-subscribe":     true,
		"oauth-poll-subscribe":     true,
	}
	scopes := strings.Fields(value)
	if len(scopes) == 0 {
		return false
	}
	seen := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		if !allowed[scope] || seen[scope] {
			return false
		}
		seen[scope] = true
	}
	return true
}

func (b *broker) exchangeToken(writer http.ResponseWriter, incoming *http.Request, form url.Values) {
	upstreamRequest, err := http.NewRequestWithContext(
		incoming.Context(),
		http.MethodPost,
		b.tokenURL,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "internal_error")
		return
	}
	upstreamRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	upstreamRequest.Header.Set("Accept", "application/json")
	response, err := b.client.Do(upstreamRequest)
	if err != nil {
		writeError(writer, http.StatusBadGateway, "upstream_unavailable")
		return
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(responseBody) > maxResponseBytes {
		writeError(writer, http.StatusBadGateway, "invalid_upstream_response")
		return
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		status := http.StatusBadGateway
		errorCode := "upstream_rejected_request"
		if response.StatusCode >= 400 && response.StatusCode < 500 {
			status = http.StatusBadRequest
			errorCode = upstreamErrorCode(responseBody)
		}
		writeError(writer, status, errorCode)
		return
	}
	var token tokenResponse
	if err := json.Unmarshal(responseBody, &token); err != nil ||
		!validOpaqueValue(token.AccessToken, 4096) ||
		!strings.EqualFold(token.TokenType, "Bearer") ||
		token.ExpiresIn <= 0 ||
		(token.RefreshToken != "" && !validOpaqueValue(token.RefreshToken, 4096)) {
		writeError(writer, http.StatusBadGateway, "invalid_upstream_response")
		return
	}
	writeJSON(writer, http.StatusOK, token)
}

func upstreamErrorCode(body []byte) string {
	var value struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &value) != nil {
		return "upstream_rejected_request"
	}
	switch value.Error {
	case "invalid_request", "invalid_client", "invalid_grant", "unauthorized_client",
		"unsupported_grant_type", "invalid_scope":
		return value.Error
	default:
		return "upstream_rejected_request"
	}
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeError(writer http.ResponseWriter, status int, code string) {
	writeJSON(writer, status, map[string]string{"error": code})
}

func main() {
	configuration, err := loadConfig(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "8080"
	}
	if _, err := strconv.Atoi(port); err != nil {
		log.Fatal("PORT must be a valid TCP port")
	}
	address := net.JoinHostPort("", port)
	server := &http.Server{
		Addr:              address,
		Handler:           newBroker(configuration, nil, tokenEndpoint).handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}

	stop, stopSignal := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignal()
	go func() {
		<-stop.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Graceful shutdown failed: %v", err)
		}
	}()

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(fmt.Errorf("OAuth broker failed to start: %w", err))
	}
}
