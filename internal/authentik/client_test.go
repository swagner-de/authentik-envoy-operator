package authentik_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/authentik-envoy-operator/authentik-envoy-operator/internal/authentik"
)

func TestNewClient(t *testing.T) {
	client := authentik.NewClient("https://authentik.example.com", "test-token")
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestClientDoRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("expected Bearer token, got %s", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json content-type, got %s", r.Header.Get("Content-Type"))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"pk": 1, "name": "test"}`))
	}))
	defer server.Close()

	client := authentik.NewClient(server.URL, "test-token")
	var result struct {
		PK   int    `json:"pk"`
		Name string `json:"name"`
	}
	err := client.Do(context.Background(), http.MethodGet, "/api/v3/test/", nil, &result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.PK != 1 || result.Name != "test" {
		t.Errorf("unexpected result: %+v", result)
	}
}

func TestClientDoRequestAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"detail": "bad request"}`))
	}))
	defer server.Close()

	client := authentik.NewClient(server.URL, "test-token")
	err := client.Do(context.Background(), http.MethodGet, "/api/v3/test/", nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	apiErr, ok := err.(*authentik.APIError)
	if !ok {
		t.Fatalf("expected APIError, got %T", err)
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", apiErr.StatusCode)
	}
	if !strings.Contains(err.Error(), "400") || !strings.Contains(err.Error(), "bad request") {
		t.Errorf("expected error to include status and detail, got %q", err.Error())
	}
}

// TestClientDoRequestFieldValidationError ensures DRF-style field errors (which
// populate neither detail nor errors) still surface via the raw body.
func TestClientDoRequestFieldValidationError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"signing_key":["This field is required."]}`))
	}))
	defer server.Close()

	client := authentik.NewClient(server.URL, "test-token")
	err := client.Do(context.Background(), http.MethodPost, "/api/v3/test/", map[string]string{}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "signing_key") {
		t.Errorf("expected field-validation body to surface in error, got %q", err.Error())
	}
}
