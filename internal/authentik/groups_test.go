package authentik_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authentik-envoy-operator/authentik-envoy-operator/internal/authentik"
)

func TestGetGroupByName(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v3/core/groups/" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("name") != "admins" {
			t.Errorf("unexpected name query: %s", r.URL.Query().Get("name"))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"pagination":{"count":1},"results":[{"pk":"group-uuid-456","name":"admins"}]}`))
	}))
	defer server.Close()

	client := authentik.NewClient(server.URL, "token")
	group, err := client.GetGroupByName(context.Background(), "admins")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if group.PK != "group-uuid-456" {
		t.Errorf("expected group-uuid-456, got %s", group.PK)
	}
}

func TestGetGroupByNameNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"pagination":{"count":0},"results":[]}`))
	}))
	defer server.Close()

	client := authentik.NewClient(server.URL, "token")
	_, err := client.GetGroupByName(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing group")
	}
}
