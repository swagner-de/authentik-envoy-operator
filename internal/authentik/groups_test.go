package authentik_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/swagner-de/authentik-envoy-operator/internal/authentik"
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
	group, err := client.GetGroupByName(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if group != nil {
		t.Fatalf("expected nil group for absent name, got %+v", group)
	}
}

func TestGetGroupByNameExactMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a substring filter returning multiple rows.
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"pagination":{"count":2},"results":[` +
			`{"pk":"uuid-admins-extra","name":"admins-extra"},` +
			`{"pk":"uuid-admins","name":"admins"}]}`))
	}))
	defer server.Close()

	client := authentik.NewClient(server.URL, "token")
	group, err := client.GetGroupByName(context.Background(), "admins")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if group.PK != "uuid-admins" {
		t.Errorf("expected exact match uuid-admins, got %s", group.PK)
	}
}

func TestGetGroupByNameNoExactMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"pagination":{"count":1},"results":[{"pk":"x","name":"admins-extra"}]}`))
	}))
	defer server.Close()

	client := authentik.NewClient(server.URL, "token")
	group, err := client.GetGroupByName(context.Background(), "admins")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if group != nil {
		t.Fatalf("expected nil group when no exact match, got %+v", group)
	}
}

func TestDeleteGroup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/api/v3/core/groups/group-uuid-789/" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := authentik.NewClient(server.URL, "token")
	if err := client.DeleteGroup(context.Background(), "group-uuid-789"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateGroup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v3/core/groups/" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"pk":"new-uuid","name":"created"}`))
	}))
	defer server.Close()

	client := authentik.NewClient(server.URL, "token")
	g, err := client.CreateGroup(context.Background(), "created")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.PK != "new-uuid" {
		t.Errorf("expected new-uuid, got %s", g.PK)
	}
}
