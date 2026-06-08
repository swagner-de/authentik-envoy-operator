package authentik_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authentik-envoy-operator/authentik-envoy-operator/internal/authentik"
)

func TestCreatePolicyBinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v3/policies/bindings/" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		var req authentik.PolicyBindingRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.Target != "app-uuid" {
			t.Errorf("unexpected target: %s", req.Target)
		}
		if req.Group != "group-uuid" {
			t.Errorf("unexpected group: %s", req.Group)
		}
		if req.Order != 0 {
			t.Errorf("unexpected order: %d", req.Order)
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"pk":"binding-uuid","target":"app-uuid","group":"group-uuid","order":0,"enabled":true}`))
	}))
	defer server.Close()

	client := authentik.NewClient(server.URL, "token")
	binding, err := client.CreatePolicyBinding(context.Background(), authentik.PolicyBindingRequest{
		Target:  "app-uuid",
		Group:   "group-uuid",
		Order:   0,
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if binding.PK != "binding-uuid" {
		t.Errorf("expected binding-uuid, got %s", binding.PK)
	}
	if binding.Target != "app-uuid" {
		t.Errorf("expected app-uuid, got %s", binding.Target)
	}
	if !binding.Enabled {
		t.Error("expected enabled to be true")
	}
}

func TestDeletePolicyBinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		if r.URL.Path != "/api/v3/policies/bindings/binding-uuid/" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := authentik.NewClient(server.URL, "token")
	err := client.DeletePolicyBinding(context.Background(), "binding-uuid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListPolicyBindings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/api/v3/policies/bindings/" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("target") != "app-uuid" {
			t.Errorf("unexpected target query: %s", r.URL.Query().Get("target"))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"pagination":{"count":2,"current":1},"results":[{"pk":"b1","target":"app-uuid","group":"g1","order":0,"enabled":true},{"pk":"b2","target":"app-uuid","group":"g2","order":1,"enabled":true}]}`))
	}))
	defer server.Close()

	client := authentik.NewClient(server.URL, "token")
	bindings, err := client.ListPolicyBindings(context.Background(), "app-uuid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(bindings) != 2 {
		t.Fatalf("expected 2 bindings, got %d", len(bindings))
	}
	if bindings[0].PK != "b1" {
		t.Errorf("expected b1, got %s", bindings[0].PK)
	}
	if bindings[1].PK != "b2" {
		t.Errorf("expected b2, got %s", bindings[1].PK)
	}
}
