package authentik_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/swagner-de/authentik-envoy-operator/internal/authentik"
)

func TestGetFlowBySlug(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v3/flows/instances/" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("slug") != "default-provider-authorization-implicit-consent" {
			t.Errorf("unexpected slug query: %s", r.URL.Query().Get("slug"))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"pagination":{"count":1},"results":[{"pk":"flow-uuid-123","slug":"default-provider-authorization-implicit-consent","name":"Authorize","designation":"authorization"}]}`))
	}))
	defer server.Close()

	client := authentik.NewClient(server.URL, "token")
	flow, err := client.GetFlowBySlug(context.Background(), "default-provider-authorization-implicit-consent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if flow.PK != "flow-uuid-123" {
		t.Errorf("expected flow-uuid-123, got %s", flow.PK)
	}
}

func TestGetFlowBySlugNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"pagination":{"count":0},"results":[]}`))
	}))
	defer server.Close()

	client := authentik.NewClient(server.URL, "token")
	flow, err := client.GetFlowBySlug(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if flow != nil {
		t.Fatalf("expected nil flow for absent slug, got %+v", flow)
	}
}
