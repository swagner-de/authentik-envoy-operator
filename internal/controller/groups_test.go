package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/swagner-de/authentik-envoy-operator/api/v1alpha1"
	"github.com/swagner-de/authentik-envoy-operator/internal/authentik"
)

func TestResolveGroupsCreatesMissing(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/core/groups/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(authentik.Group{PK: "created-uuid", Name: "new"})
			return
		}
		// GET: "existing" resolves, "new" does not
		if r.URL.Query().Get("name") == "existing" {
			json.NewEncoder(w).Encode(authentik.PaginatedResponse[authentik.Group]{
				Results: []authentik.Group{{PK: "existing-uuid", Name: "existing"}}})
			return
		}
		json.NewEncoder(w).Encode(authentik.PaginatedResponse[authentik.Group]{})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	app := &v1alpha1.OIDCApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "g", Namespace: "m"},
		Spec: v1alpha1.OIDCApplicationSpec{Groups: []v1alpha1.GroupRef{
			{Name: "existing", Create: false},
			{Name: "new", Create: true},
		}},
	}
	client := authentik.NewClient(server.URL, "t")
	byName, created, err := resolveGroups(context.Background(), client, app)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if byName["existing"] != "existing-uuid" || byName["new"] != "created-uuid" {
		t.Errorf("unexpected uuids: %v", byName)
	}
	if len(created) != 1 || created[0] != "new" {
		t.Errorf("expected created=[new], got %v", created)
	}
}

func TestResolveGroupsMissingNoCreate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(authentik.PaginatedResponse[authentik.Group]{})
	}))
	defer server.Close()
	app := &v1alpha1.OIDCApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "g", Namespace: "m"},
		Spec:       v1alpha1.OIDCApplicationSpec{Groups: []v1alpha1.GroupRef{{Name: "absent", Create: false}}},
	}
	if _, _, err := resolveGroups(context.Background(), authentik.NewClient(server.URL, "t"), app); err == nil {
		t.Fatal("expected error when a create:false group is missing")
	}
}

// TestResolveGroupsTransientErrorDoesNotCreate ensures a transient API failure on
// the group lookup is surfaced as an error (so the reconcile retries) rather than
// being mistaken for "group absent" and creating a duplicate group.
func TestResolveGroupsTransientErrorDoesNotCreate(t *testing.T) {
	var posted bool
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/core/groups/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posted = true
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(authentik.Group{PK: "dup-uuid", Name: "existing"})
			return
		}
		// GET fails transiently.
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(`{"detail":"upstream unavailable"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	app := &v1alpha1.OIDCApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "g", Namespace: "m"},
		Spec:       v1alpha1.OIDCApplicationSpec{Groups: []v1alpha1.GroupRef{{Name: "existing", Create: true}}},
	}
	_, _, err := resolveGroups(context.Background(), authentik.NewClient(server.URL, "t"), app)
	if err == nil {
		t.Fatal("expected a transient lookup error to propagate")
	}
	if posted {
		t.Error("must NOT create a group when the lookup failed transiently")
	}
}
