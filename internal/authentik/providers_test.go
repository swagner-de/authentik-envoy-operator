package authentik_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authentik-envoy-operator/authentik-envoy-operator/internal/authentik"
)

func TestCreateProvider(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v3/providers/oauth2/" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		var req authentik.OAuth2ProviderRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.Name != "test-provider" {
			t.Errorf("unexpected name: %s", req.Name)
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"pk":42,"name":"test-provider","client_id":"test-client-id","client_secret":"generated-secret"}`))
	}))
	defer server.Close()

	client := authentik.NewClient(server.URL, "token")
	provider, err := client.CreateProvider(context.Background(), authentik.OAuth2ProviderRequest{
		Name:              "test-provider",
		AuthorizationFlow: "flow-uuid",
		InvalidationFlow:  "flow-uuid",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider.PK != 42 {
		t.Errorf("expected PK 42, got %d", provider.PK)
	}
	if provider.ClientSecret != "generated-secret" {
		t.Errorf("expected generated-secret, got %s", provider.ClientSecret)
	}
}

func TestUpdateProvider(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		if r.URL.Path != "/api/v3/providers/oauth2/42/" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"pk":42,"name":"updated","client_id":"test-client-id","client_secret":"secret"}`))
	}))
	defer server.Close()

	client := authentik.NewClient(server.URL, "token")
	provider, err := client.UpdateProvider(context.Background(), 42, authentik.OAuth2ProviderRequest{
		Name:              "updated",
		AuthorizationFlow: "flow-uuid",
		InvalidationFlow:  "flow-uuid",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider.Name != "updated" {
		t.Errorf("expected updated, got %s", provider.Name)
	}
}

func TestGetProvider(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v3/providers/oauth2/42/" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"pk":42,"name":"test","client_id":"cid","client_secret":"cs"}`))
	}))
	defer server.Close()

	client := authentik.NewClient(server.URL, "token")
	provider, err := client.GetProvider(context.Background(), 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider.PK != 42 {
		t.Errorf("expected 42, got %d", provider.PK)
	}
}

func TestDeleteProvider(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		if r.URL.Path != "/api/v3/providers/oauth2/42/" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := authentik.NewClient(server.URL, "token")
	err := client.DeleteProvider(context.Background(), 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
