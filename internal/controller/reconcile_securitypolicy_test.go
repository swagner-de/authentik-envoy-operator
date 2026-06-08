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

	v1alpha1 "github.com/authentik-envoy-operator/authentik-envoy-operator/api/v1alpha1"
	"github.com/authentik-envoy-operator/authentik-envoy-operator/internal/authentik"
)

func newTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(v1alpha1.AddToScheme(s))
	utilruntime.Must(gwapiv1.Install(s))
	utilruntime.Must(egv1alpha1.AddToScheme(s))
	return s
}

func fakeAuthentikServer() *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v3/core/groups/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(authentik.PaginatedResponse[authentik.Group]{
			Results: []authentik.Group{{PK: "group-uuid-1", Name: "admins"}},
		})
	})

	mux.HandleFunc("/api/v3/crypto/certificatekeypairs/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(authentik.PaginatedResponse[authentik.CertificateKeyPair]{
			Results: []authentik.CertificateKeyPair{{PK: "signing-key-uuid", Name: "Self-signed Certificate"}},
		})
	})

	mux.HandleFunc("/api/v3/propertymappings/provider/scope/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(authentik.PaginatedResponse[authentik.ScopeMapping]{
			Results: []authentik.ScopeMapping{{PK: "mapping-uuid-1", Name: "openid", ScopeName: "openid"}},
		})
	})

	mux.HandleFunc("/api/v3/providers/oauth2/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(authentik.OAuth2Provider{
				PK:           1,
				Name:         "test-ns-test-policy",
				ClientID:     "test-ns-test-policy",
				ClientSecret: "generated-secret",
			})
			return
		}
	})

	mux.HandleFunc("/api/v3/core/applications/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(authentik.Application{
				PK:   "app-uuid",
				Name: "test-ns-test-policy",
				Slug: "test-ns-test-policy",
			})
			return
		}
	})

	mux.HandleFunc("/api/v3/policies/bindings/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(authentik.PolicyBinding{
				PK:      "binding-uuid-1",
				Target:  "app-uuid",
				Group:   "group-uuid-1",
				Enabled: true,
			})
			return
		}
	})

	return httptest.NewServer(mux)
}

func TestReconcileCreatesSecurityPolicy(t *testing.T) {
	scheme := newTestScheme()
	server := fakeAuthentikServer()
	defer server.Close()

	provider := &v1alpha1.AuthentikProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "main"},
		Spec: v1alpha1.AuthentikProviderSpec{
			Host:                  server.URL,
			APITokenSecretRef:     v1alpha1.SecretKeyReference{Name: "auth-token", Namespace: "default", Key: "token"},
			AuthorizationFlowSlug: "default-provider-authorization-implicit-consent",
			InvalidationFlowSlug:  "default-provider-invalidation-flow",
		},
		Status: v1alpha1.AuthentikProviderStatus{
			Conditions: []metav1.Condition{
				{Type: ConditionConnected, Status: metav1.ConditionTrue, LastTransitionTime: metav1.Now(), Reason: "OK"},
			},
			AuthorizationFlowUID: "auth-flow-uuid",
			InvalidationFlowUID:  "inval-flow-uuid",
		},
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "auth-token", Namespace: "default"},
		Data:       map[string][]byte{"token": []byte("fake-token")},
	}

	httpRoute := &gwapiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "my-route", Namespace: "test-ns"},
		Spec: gwapiv1.HTTPRouteSpec{
			Hostnames: []gwapiv1.Hostname{"app.example.com"},
		},
	}

	policy := &v1alpha1.OIDCPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "test-ns",
			Finalizers: []string{finalizerName},
		},
		Spec: v1alpha1.OIDCPolicySpec{
			ProviderRef: v1alpha1.ProviderRef{Name: "main"},
			TargetRefs:  []v1alpha1.TargetRef{{Name: "my-route"}},
			OIDC: v1alpha1.OIDCConfig{
				AllowedGroups:    []string{"admins"},
				SigningKey:        "Self-signed Certificate",
				PropertyMappings: []string{"openid"},
			},
		},
	}

	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(provider, secret, httpRoute, policy).
		WithStatusSubresource(policy).
		Build()

	reconciler := &OIDCPolicyReconciler{Client: k8s, Scheme: scheme}

	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-policy", Namespace: "test-ns"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	if result.RequeueAfter == 0 {
		t.Error("expected RequeueAfter > 0")
	}

	// Verify SecurityPolicy was created
	var sp egv1alpha1.SecurityPolicy
	err = k8s.Get(context.Background(), types.NamespacedName{
		Name:      "test-policy-my-route",
		Namespace: "test-ns",
	}, &sp)
	if err != nil {
		t.Fatalf("SecurityPolicy not created: %v", err)
	}

	// Verify it targets the HTTPRoute
	if len(sp.Spec.TargetRefs) != 1 {
		t.Fatalf("expected 1 targetRef, got %d", len(sp.Spec.TargetRefs))
	}
	if string(sp.Spec.TargetRefs[0].Name) != "my-route" {
		t.Errorf("expected targetRef my-route, got %s", sp.Spec.TargetRefs[0].Name)
	}

	// Verify owner reference
	if len(sp.OwnerReferences) != 1 {
		t.Fatalf("expected 1 owner reference, got %d", len(sp.OwnerReferences))
	}
	if sp.OwnerReferences[0].Name != "test-policy" {
		t.Errorf("expected owner test-policy, got %s", sp.OwnerReferences[0].Name)
	}

	// Verify OIDC config
	if sp.Spec.OIDC == nil {
		t.Fatal("expected OIDC spec")
	}
	if *sp.Spec.OIDC.ClientID != "test-ns-test-policy" {
		t.Errorf("expected clientID test-ns-test-policy, got %s", *sp.Spec.OIDC.ClientID)
	}

	// Verify client secret was synced
	var clientSecret corev1.Secret
	err = k8s.Get(context.Background(), types.NamespacedName{
		Name:      "test-policy-client-secret",
		Namespace: "test-ns",
	}, &clientSecret)
	if err != nil {
		t.Fatalf("client secret not created: %v", err)
	}
	if string(clientSecret.Data["client-secret"]) != "generated-secret" {
		t.Errorf("unexpected client secret value: %s", clientSecret.Data["client-secret"])
	}
}

func TestReconcileUpdatesSecurityPolicyOnSpecChange(t *testing.T) {
	scheme := newTestScheme()
	server := fakeAuthentikServer()
	defer server.Close()

	provider := &v1alpha1.AuthentikProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "main"},
		Spec: v1alpha1.AuthentikProviderSpec{
			Host:              server.URL,
			APITokenSecretRef: v1alpha1.SecretKeyReference{Name: "auth-token", Namespace: "default", Key: "token"},
		},
		Status: v1alpha1.AuthentikProviderStatus{
			Conditions: []metav1.Condition{
				{Type: ConditionConnected, Status: metav1.ConditionTrue, LastTransitionTime: metav1.Now(), Reason: "OK"},
			},
			AuthorizationFlowUID: "auth-flow-uuid",
			InvalidationFlowUID:  "inval-flow-uuid",
		},
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "auth-token", Namespace: "default"},
		Data:       map[string][]byte{"token": []byte("fake-token")},
	}

	httpRoute := &gwapiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "my-route", Namespace: "test-ns"},
		Spec: gwapiv1.HTTPRouteSpec{
			Hostnames: []gwapiv1.Hostname{"app.example.com"},
		},
	}

	// Pre-existing SecurityPolicy (simulating previous reconcile)
	existingSP := &egv1alpha1.SecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy-my-route",
			Namespace: "test-ns",
		},
		Spec: egv1alpha1.SecurityPolicySpec{},
	}

	policy := &v1alpha1.OIDCPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "test-ns",
			Finalizers: []string{finalizerName},
		},
		Spec: v1alpha1.OIDCPolicySpec{
			ProviderRef: v1alpha1.ProviderRef{Name: "main"},
			TargetRefs:  []v1alpha1.TargetRef{{Name: "my-route"}},
			OIDC: v1alpha1.OIDCConfig{
				AllowedGroups:      []string{"admins"},
				ForwardAccessToken: true,
				SigningKey:          "Self-signed Certificate",
				PropertyMappings:   []string{"openid"},
			},
		},
	}

	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(provider, secret, httpRoute, policy, existingSP).
		WithStatusSubresource(policy).
		Build()

	reconciler := &OIDCPolicyReconciler{Client: k8s, Scheme: scheme}

	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-policy", Namespace: "test-ns"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// Verify SecurityPolicy was updated with OIDC config
	var sp egv1alpha1.SecurityPolicy
	err = k8s.Get(context.Background(), types.NamespacedName{
		Name:      "test-policy-my-route",
		Namespace: "test-ns",
	}, &sp)
	if err != nil {
		t.Fatalf("SecurityPolicy not found: %v", err)
	}

	if sp.Spec.OIDC == nil {
		t.Fatal("expected OIDC spec after update")
	}
	if sp.Spec.OIDC.ForwardAccessToken == nil || !*sp.Spec.OIDC.ForwardAccessToken {
		t.Error("expected forwardAccessToken to be true after update")
	}
}

func TestReconcileCreatesMultipleSecurityPolicies(t *testing.T) {
	scheme := newTestScheme()
	server := fakeAuthentikServer()
	defer server.Close()

	provider := &v1alpha1.AuthentikProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "main"},
		Spec: v1alpha1.AuthentikProviderSpec{
			Host:              server.URL,
			APITokenSecretRef: v1alpha1.SecretKeyReference{Name: "auth-token", Namespace: "default", Key: "token"},
		},
		Status: v1alpha1.AuthentikProviderStatus{
			Conditions: []metav1.Condition{
				{Type: ConditionConnected, Status: metav1.ConditionTrue, LastTransitionTime: metav1.Now(), Reason: "OK"},
			},
			AuthorizationFlowUID: "auth-flow-uuid",
			InvalidationFlowUID:  "inval-flow-uuid",
		},
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "auth-token", Namespace: "default"},
		Data:       map[string][]byte{"token": []byte("fake-token")},
	}

	route1 := &gwapiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-a", Namespace: "test-ns"},
		Spec:       gwapiv1.HTTPRouteSpec{Hostnames: []gwapiv1.Hostname{"a.example.com"}},
	}
	route2 := &gwapiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-b", Namespace: "test-ns"},
		Spec:       gwapiv1.HTTPRouteSpec{Hostnames: []gwapiv1.Hostname{"b.example.com"}},
	}

	policy := &v1alpha1.OIDCPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "multi-policy",
			Namespace:  "test-ns",
			Finalizers: []string{finalizerName},
		},
		Spec: v1alpha1.OIDCPolicySpec{
			ProviderRef: v1alpha1.ProviderRef{Name: "main"},
			TargetRefs:  []v1alpha1.TargetRef{{Name: "route-a"}, {Name: "route-b"}},
			OIDC: v1alpha1.OIDCConfig{
				AllowedGroups: []string{"admins"},
				SigningKey:     "Self-signed Certificate",
			},
		},
	}

	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(provider, secret, route1, route2, policy).
		WithStatusSubresource(policy).
		Build()

	reconciler := &OIDCPolicyReconciler{Client: k8s, Scheme: scheme}

	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "multi-policy", Namespace: "test-ns"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// Verify both SecurityPolicies were created
	var spA egv1alpha1.SecurityPolicy
	err = k8s.Get(context.Background(), types.NamespacedName{
		Name: "multi-policy-route-a", Namespace: "test-ns",
	}, &spA)
	if err != nil {
		t.Fatalf("SecurityPolicy for route-a not created: %v", err)
	}
	if string(spA.Spec.TargetRefs[0].Name) != "route-a" {
		t.Errorf("expected targetRef route-a, got %s", spA.Spec.TargetRefs[0].Name)
	}

	var spB egv1alpha1.SecurityPolicy
	err = k8s.Get(context.Background(), types.NamespacedName{
		Name: "multi-policy-route-b", Namespace: "test-ns",
	}, &spB)
	if err != nil {
		t.Fatalf("SecurityPolicy for route-b not created: %v", err)
	}
	if string(spB.Spec.TargetRefs[0].Name) != "route-b" {
		t.Errorf("expected targetRef route-b, got %s", spB.Spec.TargetRefs[0].Name)
	}
}
