package authentik_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authentik-envoy-operator/authentik-envoy-operator/internal/authentik"
)

func TestCreateApplication(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v3/core/applications/" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		var req authentik.ApplicationRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.Name != "Test App" {
			t.Errorf("unexpected name: %s", req.Name)
		}
		if req.Slug != "test-app" {
			t.Errorf("unexpected slug: %s", req.Slug)
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"pk":"app-uuid","name":"Test App","slug":"test-app","provider":42}`))
	}))
	defer server.Close()

	client := authentik.NewClient(server.URL, "token")
	app, err := client.CreateApplication(context.Background(), authentik.ApplicationRequest{
		Name:     "Test App",
		Slug:     "test-app",
		Provider: 42,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if app.PK != "app-uuid" {
		t.Errorf("expected app-uuid, got %s", app.PK)
	}
	if app.Slug != "test-app" {
		t.Errorf("expected test-app, got %s", app.Slug)
	}
	if app.Provider != 42 {
		t.Errorf("expected provider 42, got %d", app.Provider)
	}
}

func TestUpdateApplication(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		if r.URL.Path != "/api/v3/core/applications/test-app/" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		var req authentik.ApplicationRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.Name != "Updated App" {
			t.Errorf("unexpected name: %s", req.Name)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"pk":"app-uuid","name":"Updated App","slug":"test-app","provider":42}`))
	}))
	defer server.Close()

	client := authentik.NewClient(server.URL, "token")
	app, err := client.UpdateApplication(context.Background(), "test-app", authentik.ApplicationRequest{
		Name:     "Updated App",
		Slug:     "test-app",
		Provider: 42,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if app.Name != "Updated App" {
		t.Errorf("expected Updated App, got %s", app.Name)
	}
}

func TestGetApplication(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/api/v3/core/applications/test-app/" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"pk":"app-uuid","name":"Test App","slug":"test-app","provider":42}`))
	}))
	defer server.Close()

	client := authentik.NewClient(server.URL, "token")
	app, err := client.GetApplication(context.Background(), "test-app")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if app.PK != "app-uuid" {
		t.Errorf("expected app-uuid, got %s", app.PK)
	}
	if app.Slug != "test-app" {
		t.Errorf("expected test-app, got %s", app.Slug)
	}
}

func TestDeleteApplication(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		if r.URL.Path != "/api/v3/core/applications/test-app/" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := authentik.NewClient(server.URL, "token")
	err := client.DeleteApplication(context.Background(), "test-app")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
