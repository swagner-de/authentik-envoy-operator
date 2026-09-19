package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	egv1alpha1 "github.com/envoyproxy/gateway/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/swagner-de/authentik-envoy-operator/api/v1alpha1"
	"github.com/swagner-de/authentik-envoy-operator/internal/authentik"
)

// newTestScheme builds a runtime.Scheme registered with the types the
// controller tests need. Relocated here from the deleted OIDCPolicy tests
// because the AuthentikProvider tests are its remaining consumer.
func newTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(v1alpha1.AddToScheme(s))
	utilruntime.Must(gwapiv1.Install(s))
	utilruntime.Must(egv1alpha1.AddToScheme(s))
	return s
}

func fakeAuthentikFlowServer() *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v3/flows/instances/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(authentik.PaginatedResponse[authentik.Flow]{
			Results: []authentik.Flow{{PK: "flow-uuid", Slug: "default-flow", Name: "Default"}},
		})
	})

	return httptest.NewServer(mux)
}

func TestAuthentikProviderReconcileConnects(t *testing.T) {
	scheme := newTestScheme()
	server := fakeAuthentikFlowServer()
	defer server.Close()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "api-token", Namespace: "default"},
		Data:       map[string][]byte{"token": []byte("fake-token")},
	}

	provider := &v1alpha1.AuthentikProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "test-provider"},
		Spec: v1alpha1.AuthentikProviderSpec{
			Host:                  server.URL,
			APITokenSecretRef:     v1alpha1.SecretKeyReference{Name: "api-token", Namespace: "default", Key: "token"},
			AuthorizationFlowSlug: "default-flow",
			InvalidationFlowSlug:  "default-flow",
		},
	}

	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret, provider).
		WithStatusSubresource(provider).
		Build()

	reconciler := &AuthentikProviderReconciler{Client: k8s, Scheme: scheme}

	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-provider"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// Verify status was updated with flow UIDs
	var updated v1alpha1.AuthentikProvider
	if err := k8s.Get(context.Background(), types.NamespacedName{Name: "test-provider"}, &updated); err != nil {
		t.Fatalf("failed to get provider: %v", err)
	}

	if updated.Status.AuthorizationFlowUID != "flow-uuid" {
		t.Errorf("expected AuthorizationFlowUID flow-uuid, got %s", updated.Status.AuthorizationFlowUID)
	}
	if updated.Status.InvalidationFlowUID != "flow-uuid" {
		t.Errorf("expected InvalidationFlowUID flow-uuid, got %s", updated.Status.InvalidationFlowUID)
	}
}

func TestAuthentikProviderReconcileSecretNotFound(t *testing.T) {
	scheme := newTestScheme()

	provider := &v1alpha1.AuthentikProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "test-provider"},
		Spec: v1alpha1.AuthentikProviderSpec{
			Host:              "https://authentik.example.com",
			APITokenSecretRef: v1alpha1.SecretKeyReference{Name: "missing-secret", Namespace: "default", Key: "token"},
		},
	}

	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(provider).
		WithStatusSubresource(provider).
		Build()

	reconciler := &AuthentikProviderReconciler{Client: k8s, Scheme: scheme}

	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-provider"},
	})
	if err != nil {
		t.Fatalf("Reconcile should not return error for missing secret (requeues): %v", err)
	}

	// Verify condition was set to not connected
	var updated v1alpha1.AuthentikProvider
	if err := k8s.Get(context.Background(), types.NamespacedName{Name: "test-provider"}, &updated); err != nil {
		t.Fatalf("failed to get provider: %v", err)
	}

	if len(updated.Status.Conditions) == 0 {
		t.Fatal("expected status conditions to be set")
	}
	if updated.Status.Conditions[0].Status != metav1.ConditionFalse {
		t.Errorf("expected condition False, got %s", updated.Status.Conditions[0].Status)
	}
}

func TestAuthentikProviderReconcileNotFound(t *testing.T) {
	scheme := newTestScheme()

	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	reconciler := &AuthentikProviderReconciler{Client: k8s, Scheme: scheme}

	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "nonexistent"},
	})
	if err != nil {
		t.Fatalf("Reconcile should not error for not-found resource: %v", err)
	}
}
