package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	egv1alpha1 "github.com/envoyproxy/gateway/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/swagner-de/authentik-envoy-operator/api/v1alpha1"
	"github.com/swagner-de/authentik-envoy-operator/internal/authentik"
)

// fakeServerState tracks side-effecting calls so tests can assert on them.
type fakeServerState struct {
	providerPost         bool
	appPost              bool
	providerRedirectURIs []authentik.RedirectURI
	clientSecret         *string
	discoveryFailure     bool
}

type secretRelevantState struct {
	Data            map[string][]byte
	Labels          map[string]string
	Annotations     map[string]string
	OwnerReferences []metav1.OwnerReference
	Type            corev1.SecretType
}

func relevantSecretState(secret *corev1.Secret) secretRelevantState {
	copy := secret.DeepCopy()
	return secretRelevantState{
		Data:            copy.Data,
		Labels:          copy.Labels,
		Annotations:     copy.Annotations,
		OwnerReferences: copy.OwnerReferences,
		Type:            copy.Type,
	}
}

// fakeAuthentikServer serves every endpoint the reconciler hits during a
// fresh-create pass. adoptExisting=true makes GET /applications/<slug>/ and the
// linked provider resolve to pre-existing objects (exercising the adoption path).
func fakeAuthentikServer(state *fakeServerState, adoptExisting bool) *httptest.Server {
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

	// Providers: GET /<id>/ resolves an existing provider; GET ?name= is the
	// orphan-recovery lookup (empty ⇒ triggers create); POST creates.
	mux.HandleFunc("/api/v3/providers/oauth2/", func(w http.ResponseWriter, r *http.Request) {
		clientSecret := "generated-secret"
		if state.clientSecret != nil {
			clientSecret = *state.clientSecret
		}
		switch {
		case r.Method == http.MethodPost:
			state.providerPost = true
			var req authentik.OAuth2ProviderRequest
			json.NewDecoder(r.Body).Decode(&req)
			state.providerRedirectURIs = req.RedirectURIs
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(authentik.OAuth2Provider{
				PK: 1, Name: "test-ns-test-app", ClientID: "test-ns-test-app", ClientSecret: clientSecret,
			})
		case r.Method == http.MethodGet && r.URL.Query().Has("name"):
			// Orphan recovery lookup: no match ⇒ empty results.
			json.NewEncoder(w).Encode(authentik.PaginatedResponse[authentik.OAuth2Provider]{})
		case r.Method == http.MethodGet:
			// GET /<id>/ — the adopted provider linked to the existing app.
			json.NewEncoder(w).Encode(authentik.OAuth2Provider{
				PK: 7, Name: "test-ns-test-app", ClientID: "test-ns-test-app",
				ClientSecret:           clientSecret,
				ClientType:             "confidential",
				AuthorizationFlow:      "auth-flow-uuid",
				InvalidationFlow:       "inval-flow-uuid",
				SigningKey:             "signing-key-uuid",
				GrantTypes:             []string{"authorization_code", "refresh_token"},
				IssuerMode:             "per_provider",
				IncludeClaimsInIDToken: true,
				PropertyMappings:       []string{"mapping-uuid-1"},
			})
		}
	})

	// Applications: GET /<slug>/ 404s on fresh create, returns an app when
	// adopting; POST/PUT echo.
	mux.HandleFunc("/api/v3/core/applications/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			state.appPost = true
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(authentik.Application{PK: "app-uuid", Name: "test-app", Slug: "test-ns-test-app", Provider: 1})
		case http.MethodPut:
			json.NewEncoder(w).Encode(authentik.Application{PK: "app-uuid", Name: "test-app", Slug: "test-ns-test-app", Provider: 1})
		case http.MethodGet:
			if adoptExisting {
				json.NewEncoder(w).Encode(authentik.Application{
					PK: "existing-app-uuid", Name: "test-app", Slug: "test-ns-test-app", Provider: 7, PolicyEngineMode: "any",
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"detail":"Not found."}`))
		}
	})

	mux.HandleFunc("/api/v3/policies/bindings/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(authentik.PolicyBinding{PK: "binding-uuid-1", Target: "app-uuid", Group: "group-uuid-1", Enabled: true})
		case http.MethodGet:
			json.NewEncoder(w).Encode(authentik.PaginatedResponse[authentik.PolicyBinding]{})
		}
	})

	mux.HandleFunc("/application/o/", func(w http.ResponseWriter, r *http.Request) {
		if state.discoveryFailure {
			http.Error(w, "discovery unavailable", http.StatusServiceUnavailable)
			return
		}
		// .well-known/openid-configuration discovery document.
		json.NewEncoder(w).Encode(authentik.DiscoveryDocument{
			Issuer:                "https://authentik.example.com/application/o/test-ns-test-app/",
			AuthorizationEndpoint: "https://authentik.example.com/application/o/authorize/",
			TokenEndpoint:         "https://authentik.example.com/application/o/token/",
			UserinfoEndpoint:      "https://authentik.example.com/application/o/userinfo/",
			JWKSURI:               "https://authentik.example.com/application/o/test-ns-test-app/jwks/",
			EndSessionEndpoint:    "https://authentik.example.com/application/o/end-session/",
		})
	})

	return httptest.NewServer(mux)
}

func connectedProvider(host string) *v1alpha1.AuthentikProvider {
	return &v1alpha1.AuthentikProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "main"},
		Spec: v1alpha1.AuthentikProviderSpec{
			Host:              host,
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
}

func tokenSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "auth-token", Namespace: "default"},
		Data:       map[string][]byte{"token": []byte("fake-token")},
	}
}

func TestReconcileStandalone(t *testing.T) {
	scheme := newTestScheme()
	state := &fakeServerState{}
	server := fakeAuthentikServer(state, false)
	defer server.Close()

	app := &v1alpha1.OIDCApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", UID: "app-uid", Finalizers: []string{finalizerName}},
		Spec: v1alpha1.OIDCApplicationSpec{
			ProviderRef:      v1alpha1.ProviderRef{Name: "main"},
			SigningKey:       "Self-signed Certificate",
			PropertyMappings: []string{"openid"},
			Groups:           []v1alpha1.GroupRef{{Name: "admins"}},
			SecretName:       "custom-credentials",
			SecretTemplate: map[string]string{
				"CLIENT":     "{{ .ClientID }}",
				"CREDENTIAL": "{{ .ClientSecret }}",
				"ISSUER":     "{{ .Issuer }}",
			},
		},
	}
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "custom-credentials", Namespace: "test-ns", Labels: map[string]string{"preserved": "true"}},
		Data:       map[string][]byte{"stale": []byte("must-be-replaced")},
	}

	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(connectedProvider(server.URL), tokenSecret(), app, existing).
		WithStatusSubresource(app).
		Build()

	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-app", Namespace: "test-ns"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	if result.RequeueAfter == 0 {
		t.Error("expected RequeueAfter > 0")
	}

	// No SecurityPolicy for a standalone app (no targetRefs).
	var spList egv1alpha1.SecurityPolicyList
	if err := k8s.List(context.Background(), &spList); err != nil {
		t.Fatalf("listing SecurityPolicies: %v", err)
	}
	if len(spList.Items) != 0 {
		t.Errorf("expected no SecurityPolicy in standalone mode, got %d", len(spList.Items))
	}

	// The application Secret contains exactly the rendered template entries.
	var cred corev1.Secret
	if err := k8s.Get(context.Background(), types.NamespacedName{Name: "custom-credentials", Namespace: "test-ns"}, &cred); err != nil {
		t.Fatalf("credentials secret not created: %v", err)
	}
	wantData := map[string][]byte{
		"CLIENT":     []byte("test-ns-test-app"),
		"CREDENTIAL": []byte("generated-secret"),
		"ISSUER":     []byte("https://authentik.example.com/application/o/test-ns-test-app/"),
	}
	if !reflect.DeepEqual(cred.Data, wantData) {
		t.Errorf("unexpected application Secret data: %#v", cred.Data)
	}
	if !metav1.IsControlledBy(&cred, app) {
		t.Errorf("application Secret is not controlled by OIDCApplication: %+v", cred.OwnerReferences)
	}
	if got := cred.Labels[secretRoleLabel]; got != secretRoleApplication {
		t.Errorf("application Secret role label = %q, want %q", got, secretRoleApplication)
	}
	if got := cred.Labels["preserved"]; got != "true" {
		t.Errorf("unrelated Secret label = %q, want true", got)
	}

	// Status reflects the created provider + app.
	var updated v1alpha1.OIDCApplication
	if err := k8s.Get(context.Background(), types.NamespacedName{Name: "test-app", Namespace: "test-ns"}, &updated); err != nil {
		t.Fatalf("get app: %v", err)
	}
	if updated.Status.Authentik == nil || updated.Status.Authentik.ProviderID != 1 {
		t.Errorf("expected providerID 1, got %+v", updated.Status.Authentik)
	}
	if updated.Status.SecretName != "custom-credentials" {
		t.Errorf("status.secretName = %q, want custom-credentials", updated.Status.SecretName)
	}
	if updated.Status.Conditions[0].Status != metav1.ConditionTrue {
		t.Errorf("expected Ready True, got %s", updated.Status.Conditions[0].Status)
	}
}

func TestReconcileStandaloneWithoutTemplateCreatesNoSecret(t *testing.T) {
	scheme := newTestScheme()
	state := &fakeServerState{discoveryFailure: true}
	server := fakeAuthentikServer(state, false)
	defer server.Close()

	app := &v1alpha1.OIDCApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", Finalizers: []string{finalizerName}},
		Spec: v1alpha1.OIDCApplicationSpec{
			ProviderRef: v1alpha1.ProviderRef{Name: "main"},
			SigningKey:  "Self-signed Certificate",
			Groups:      []v1alpha1.GroupRef{{Name: "admins"}},
		},
	}
	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(connectedProvider(server.URL), tokenSecret(), app).
		WithStatusSubresource(app).
		Build()
	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: app.Name, Namespace: app.Namespace}}); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	var secrets corev1.SecretList
	if err := k8s.List(context.Background(), &secrets, client.InNamespace(app.Namespace)); err != nil {
		t.Fatalf("list Secrets: %v", err)
	}
	if len(secrets.Items) != 0 {
		t.Errorf("expected no application Secrets, got %v", secrets.Items)
	}
	var updated v1alpha1.OIDCApplication
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(app), &updated); err != nil {
		t.Fatalf("get app: %v", err)
	}
	if updated.Status.SecretName != "" {
		t.Errorf("status.secretName = %q, want empty", updated.Status.SecretName)
	}
	condition := meta.FindStatusCondition(updated.Status.Conditions, ConditionReady)
	if condition == nil || condition.Status != metav1.ConditionTrue {
		t.Fatalf("Ready condition = %+v, want True", condition)
	}
}

func TestReconcileEnvoyMode(t *testing.T) {
	scheme := newTestScheme()
	state := &fakeServerState{discoveryFailure: true}
	server := fakeAuthentikServer(state, false)
	defer server.Close()

	route := &gwapiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "my-route", Namespace: "test-ns"},
		Spec:       gwapiv1.HTTPRouteSpec{Hostnames: []gwapiv1.Hostname{"app.example.com"}},
	}

	app := &v1alpha1.OIDCApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", UID: "app-uid", Finalizers: []string{finalizerName}},
		Spec: v1alpha1.OIDCApplicationSpec{
			ProviderRef: v1alpha1.ProviderRef{Name: "main"},
			SigningKey:  "Self-signed Certificate",
			Groups:      []v1alpha1.GroupRef{{Name: "admins"}},
			TargetRefs:  []v1alpha1.TargetRef{{Name: "my-route"}},
		},
	}
	existingEnvoySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: app.EnvoySecretName(), Namespace: app.Namespace},
		Data:       map[string][]byte{"client-secret": []byte("stale-secret")},
	}
	existingPolicy := BuildSecurityPolicy(app, app.Spec.TargetRefs[0], SecurityPolicyParams{
		AuthentikHost:   "https://stale.example.com",
		ApplicationSlug: "stale-slug",
		ClientID:        "stale-client-id",
		SecretName:      app.EnvoySecretName(),
	})
	if err := controllerutil.SetControllerReference(app, existingEnvoySecret, scheme); err != nil {
		t.Fatalf("set Envoy Secret owner: %v", err)
	}

	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(connectedProvider(server.URL), tokenSecret(), route, app, existingEnvoySecret, existingPolicy).
		WithStatusSubresource(app).
		Build()

	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-app", Namespace: "test-ns"},
	}); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	var sp egv1alpha1.SecurityPolicy
	if err := k8s.Get(context.Background(), types.NamespacedName{Name: "test-app-my-route", Namespace: "test-ns"}, &sp); err != nil {
		t.Fatalf("SecurityPolicy not created: %v", err)
	}
	if len(sp.Spec.TargetRefs) != 1 || string(sp.Spec.TargetRefs[0].Name) != "my-route" {
		t.Errorf("SecurityPolicy targetRef wrong: %+v", sp.Spec.TargetRefs)
	}
	if got := string(sp.Spec.OIDC.ClientSecret.Name); got != app.EnvoySecretName() {
		t.Errorf("SecurityPolicy client Secret = %q, want %q", got, app.EnvoySecretName())
	}
	wantIssuer := server.URL + "/application/o/test-ns-test-app/"
	if got := sp.Spec.OIDC.Provider.Issuer; got != wantIssuer {
		t.Errorf("SecurityPolicy issuer = %q, want %q", got, wantIssuer)
	}
	wantJWKS := server.URL + "/application/o/test-ns-test-app/jwks/"
	if got := sp.Spec.JWT.Providers[0].RemoteJWKS.URI; got != wantJWKS {
		t.Errorf("SecurityPolicy JWKS URI = %q, want %q", got, wantJWKS)
	}

	var envoySecret corev1.Secret
	if err := k8s.Get(context.Background(), types.NamespacedName{Name: app.EnvoySecretName(), Namespace: app.Namespace}, &envoySecret); err != nil {
		t.Fatalf("Envoy Secret not created: %v", err)
	}
	wantEnvoyData := map[string][]byte{"client-secret": []byte("generated-secret")}
	if !reflect.DeepEqual(envoySecret.Data, wantEnvoyData) {
		t.Errorf("unexpected Envoy Secret data: %#v", envoySecret.Data)
	}
	if !metav1.IsControlledBy(&envoySecret, app) {
		t.Errorf("Envoy Secret is not controlled by OIDCApplication: %+v", envoySecret.OwnerReferences)
	}
	if got := envoySecret.Labels[secretRoleLabel]; got != secretRoleEnvoy {
		t.Errorf("Envoy Secret role label = %q, want %q", got, secretRoleEnvoy)
	}
	var applicationSecret corev1.Secret
	if err := k8s.Get(context.Background(), types.NamespacedName{Name: app.EffectiveSecretName(), Namespace: app.Namespace}, &applicationSecret); !apierrors.IsNotFound(err) {
		t.Fatalf("application Secret without template should be absent, got error %v", err)
	}

	// The route hostname (app.example.com) must derive a callback redirect URI
	// on the created provider request.
	wantURI := authentik.RedirectURI{
		MatchingMode:    "strict",
		URL:             "https://app.example.com/oauth2/callback",
		RedirectURIType: "authorization",
	}
	found := false
	for _, u := range state.providerRedirectURIs {
		if u == wantURI {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected derived redirect URI %+v, got %+v", wantURI, state.providerRedirectURIs)
	}

	// Assert via status that reconciliation succeeded end-to-end.
	var updated v1alpha1.OIDCApplication
	if err := k8s.Get(context.Background(), types.NamespacedName{Name: "test-app", Namespace: "test-ns"}, &updated); err != nil {
		t.Fatalf("get app: %v", err)
	}
	if len(updated.Status.SecurityPolicies) != 1 || updated.Status.SecurityPolicies[0].Name != "test-app-my-route" {
		t.Errorf("unexpected SecurityPolicies status: %+v", updated.Status.SecurityPolicies)
	}
	if updated.Status.SecretName != "" {
		t.Errorf("status.secretName = %q, want empty", updated.Status.SecretName)
	}
	condition := meta.FindStatusCondition(updated.Status.Conditions, ConditionReady)
	if condition == nil || condition.Status != metav1.ConditionTrue {
		t.Fatalf("Ready condition = %+v, want True", condition)
	}
}

func TestReconcileKeepsApplicationAndEnvoyFallbacksSeparate(t *testing.T) {
	scheme := newTestScheme()
	omitted := ""
	state := &fakeServerState{clientSecret: &omitted}
	server := fakeAuthentikServer(state, false)
	defer server.Close()

	route := &gwapiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "my-route", Namespace: "test-ns"},
		Spec:       gwapiv1.HTTPRouteSpec{Hostnames: []gwapiv1.Hostname{"app.example.com"}},
	}
	app := &v1alpha1.OIDCApplication{
		TypeMeta:   metav1.TypeMeta{APIVersion: v1alpha1.GroupVersion.String(), Kind: "OIDCApplication"},
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", UID: "app-uid", Finalizers: []string{finalizerName}},
		Spec: v1alpha1.OIDCApplicationSpec{
			ProviderRef: v1alpha1.ProviderRef{Name: "main"},
			SigningKey:  "Self-signed Certificate",
			Groups:      []v1alpha1.GroupRef{{Name: "admins"}},
			TargetRefs:  []v1alpha1.TargetRef{{Name: "my-route"}},
			SecretTemplate: map[string]string{
				"password": "prefix-{{ .ClientSecret }}",
			},
		},
	}
	applicationSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: app.EffectiveSecretName(), Namespace: app.Namespace},
		Data:       map[string][]byte{"password": []byte("previous-rendered")},
	}
	envoySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: app.EnvoySecretName(), Namespace: app.Namespace},
		Data:       map[string][]byte{"client-secret": []byte("recovered-secret")},
	}
	if err := controllerutil.SetControllerReference(app, applicationSecret, scheme); err != nil {
		t.Fatalf("set application Secret owner: %v", err)
	}
	if err := controllerutil.SetControllerReference(app, envoySecret, scheme); err != nil {
		t.Fatalf("set Envoy Secret owner: %v", err)
	}

	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(connectedProvider(server.URL), tokenSecret(), route, app, applicationSecret, envoySecret).
		WithStatusSubresource(app).
		Build()
	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	var updatedApplication corev1.Secret
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(applicationSecret), &updatedApplication); err != nil {
		t.Fatalf("get application Secret: %v", err)
	}
	if got := updatedApplication.Data["password"]; !reflect.DeepEqual(got, applicationSecret.Data["password"]) {
		t.Errorf("application dependent entry = %q, want exact previous bytes %q", got, applicationSecret.Data["password"])
	}
	var updatedEnvoy corev1.Secret
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(envoySecret), &updatedEnvoy); err != nil {
		t.Fatalf("get Envoy Secret: %v", err)
	}
	if got := string(updatedEnvoy.Data["client-secret"]); got != "recovered-secret" {
		t.Errorf("preserved Envoy client secret = %q, want recovered-secret", got)
	}
}

func TestReconcileStandalonePreservesDependentTemplateDataWithoutEnvoyRecovery(t *testing.T) {
	scheme := newTestScheme()
	omitted := ""
	state := &fakeServerState{clientSecret: &omitted}
	server := fakeAuthentikServer(state, false)
	defer server.Close()

	app := &v1alpha1.OIDCApplication{
		TypeMeta:   metav1.TypeMeta{APIVersion: v1alpha1.GroupVersion.String(), Kind: "OIDCApplication"},
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", UID: "app-uid", Finalizers: []string{finalizerName}},
		Spec: v1alpha1.OIDCApplicationSpec{
			ProviderRef: v1alpha1.ProviderRef{Name: "main"},
			SigningKey:  "Self-signed Certificate",
			Groups:      []v1alpha1.GroupRef{{Name: "admins"}},
			SecretTemplate: map[string]string{
				"credentials": "prefix-{{ .ClientSecret }}",
				"issuer":      "{{ .Issuer }}",
			},
		},
	}
	applicationSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: app.EffectiveSecretName(), Namespace: app.Namespace},
		Data: map[string][]byte{
			"credentials": {0xff, 0x00, 0x7f},
			"issuer":      []byte("old-issuer"),
		},
	}
	staleEnvoySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: app.EnvoySecretName(), Namespace: app.Namespace},
		Data:       map[string][]byte{"client-secret": []byte("must-not-be-used")},
	}
	if err := controllerutil.SetControllerReference(app, applicationSecret, scheme); err != nil {
		t.Fatalf("set application Secret owner: %v", err)
	}
	if err := controllerutil.SetControllerReference(app, staleEnvoySecret, scheme); err != nil {
		t.Fatalf("set stale Envoy Secret owner: %v", err)
	}

	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(connectedProvider(server.URL), tokenSecret(), app, applicationSecret, staleEnvoySecret).
		WithStatusSubresource(app).
		Build()
	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	var updated corev1.Secret
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(applicationSecret), &updated); err != nil {
		t.Fatalf("get application Secret: %v", err)
	}
	if got, want := updated.Data["credentials"], applicationSecret.Data["credentials"]; !reflect.DeepEqual(got, want) {
		t.Errorf("dependent entry = %v, want exact previous bytes %v", got, want)
	}
	if got := string(updated.Data["issuer"]); got != "https://authentik.example.com/application/o/test-ns-test-app/" {
		t.Errorf("issuer = %q, want refreshed discovery issuer", got)
	}
	var deletedEnvoy corev1.Secret
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(staleEnvoySecret), &deletedEnvoy); !apierrors.IsNotFound(err) {
		t.Fatalf("stale Envoy Secret should be deleted, got error %v", err)
	}
}

func TestReconcileInvalidTemplatePreservesSecretAndRedactsCondition(t *testing.T) {
	scheme := newTestScheme()
	state := &fakeServerState{}
	server := fakeAuthentikServer(state, false)
	defer server.Close()

	app := &v1alpha1.OIDCApplication{
		TypeMeta:   metav1.TypeMeta{APIVersion: v1alpha1.GroupVersion.String(), Kind: "OIDCApplication"},
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", UID: "app-uid", Finalizers: []string{finalizerName}},
		Spec: v1alpha1.OIDCApplicationSpec{
			ProviderRef:    v1alpha1.ProviderRef{Name: "main"},
			SigningKey:     "Self-signed Certificate",
			Groups:         []v1alpha1.GroupRef{{Name: "admins"}},
			SecretTemplate: map[string]string{"BROKEN_KEY": "previous-data-{{ .ClientSecret }}-{{ .Unknown }}"},
		},
		Status: v1alpha1.OIDCApplicationStatus{SecretName: "test-app-oidc"},
	}
	previousData := map[string][]byte{
		"BROKEN_KEY": []byte("previous-data-must-not-leak"),
		"binary":     {0xff, 0x00, 0x7f},
	}
	applicationSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: app.EffectiveSecretName(), Namespace: app.Namespace},
		Data:       previousData,
	}
	if err := controllerutil.SetControllerReference(app, applicationSecret, scheme); err != nil {
		t.Fatalf("set application Secret owner: %v", err)
	}

	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(connectedProvider(server.URL), tokenSecret(), app, applicationSecret).
		WithStatusSubresource(app).
		Build()
	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)})
	if err != nil {
		t.Fatalf("Reconcile should record and requeue the template error: %v", err)
	}
	if result.RequeueAfter == 0 {
		t.Error("expected requeue after invalid template")
	}

	var unchanged corev1.Secret
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(applicationSecret), &unchanged); err != nil {
		t.Fatalf("get application Secret: %v", err)
	}
	if !reflect.DeepEqual(unchanged.Data, previousData) {
		t.Errorf("application Secret data = %#v, want exact previous data %#v", unchanged.Data, previousData)
	}

	var updatedApp v1alpha1.OIDCApplication
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(app), &updatedApp); err != nil {
		t.Fatalf("get app: %v", err)
	}
	condition := meta.FindStatusCondition(updatedApp.Status.Conditions, ConditionReady)
	if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "SecretSyncFailed" {
		t.Fatalf("Ready condition = %+v, want False/SecretSyncFailed", condition)
	}
	if !strings.Contains(condition.Message, "BROKEN_KEY") {
		t.Errorf("condition message %q does not identify failing key", condition.Message)
	}
	for _, leaked := range []string{"previous-data-must-not-leak", "generated-secret"} {
		if strings.Contains(condition.Message, leaked) {
			t.Errorf("condition message %q leaks %q", condition.Message, leaked)
		}
	}
}

func TestReconcileSecretClientFailures(t *testing.T) {
	tests := map[string]struct {
		existingDesired bool
		staleSecret     bool
		interceptors    func(string) interceptor.Funcs
	}{
		"create": {
			interceptors: func(sentinel string) interceptor.Funcs {
				return interceptor.Funcs{
					Create: func(ctx context.Context, delegate client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
						if _, ok := obj.(*corev1.Secret); ok {
							return errors.New(sentinel)
						}
						return delegate.Create(ctx, obj, opts...)
					},
				}
			},
		},
		"update": {
			existingDesired: true,
			interceptors: func(sentinel string) interceptor.Funcs {
				return interceptor.Funcs{
					Update: func(ctx context.Context, delegate client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
						if _, ok := obj.(*corev1.Secret); ok {
							return errors.New(sentinel)
						}
						return delegate.Update(ctx, obj, opts...)
					},
				}
			},
		},
		"stale delete": {
			existingDesired: true,
			staleSecret:     true,
			interceptors: func(sentinel string) interceptor.Funcs {
				return interceptor.Funcs{
					Delete: func(ctx context.Context, delegate client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
						if _, ok := obj.(*corev1.Secret); ok {
							return errors.New(sentinel)
						}
						return delegate.Delete(ctx, obj, opts...)
					},
				}
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			scheme := newTestScheme()
			state := &fakeServerState{}
			server := fakeAuthentikServer(state, false)
			defer server.Close()

			app := &v1alpha1.OIDCApplication{
				TypeMeta:   metav1.TypeMeta{APIVersion: v1alpha1.GroupVersion.String(), Kind: "OIDCApplication"},
				ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", UID: "app-uid", Finalizers: []string{finalizerName}},
				Spec: v1alpha1.OIDCApplicationSpec{
					ProviderRef:    v1alpha1.ProviderRef{Name: "main"},
					SigningKey:     "Self-signed Certificate",
					Groups:         []v1alpha1.GroupRef{{Name: "admins"}},
					SecretTemplate: map[string]string{"value": "new-value"},
				},
			}
			objects := []client.Object{connectedProvider(server.URL), tokenSecret(), app}
			var desired, stale *corev1.Secret
			if test.existingDesired {
				desired = &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:        app.EffectiveSecretName(),
						Namespace:   app.Namespace,
						Labels:      map[string]string{"preserved": "label"},
						Annotations: map[string]string{"preserved": "annotation"},
					},
					Data: map[string][]byte{"value": []byte("old-value")},
					Type: corev1.SecretTypeOpaque,
				}
				if err := controllerutil.SetControllerReference(app, desired, scheme); err != nil {
					t.Fatalf("set desired Secret owner: %v", err)
				}
				objects = append(objects, desired)
			}
			if test.staleSecret {
				stale = &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "stale-secret", Namespace: app.Namespace, Labels: map[string]string{secretRoleLabel: secretRoleApplication, "preserved": "stale"}},
					Data:       map[string][]byte{"value": []byte("stale-value")},
				}
				if err := controllerutil.SetControllerReference(app, stale, scheme); err != nil {
					t.Fatalf("set stale Secret owner: %v", err)
				}
				objects = append(objects, stale)
			}

			baseClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).WithStatusSubresource(app).Build()
			sentinel := "sensitive-kubernetes-error-" + strings.ReplaceAll(name, " ", "-")
			k8s := interceptor.NewClient(baseClient, test.interceptors(sentinel))
			reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
			result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)})
			if err != nil {
				t.Fatalf("Reconcile should record and requeue the Secret error: %v", err)
			}
			if result.RequeueAfter == 0 {
				t.Error("expected requeue after Secret client failure")
			}

			var updatedApp v1alpha1.OIDCApplication
			if err := baseClient.Get(context.Background(), client.ObjectKeyFromObject(app), &updatedApp); err != nil {
				t.Fatalf("get app: %v", err)
			}
			condition := meta.FindStatusCondition(updatedApp.Status.Conditions, ConditionReady)
			if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "SecretSyncFailed" {
				t.Fatalf("Ready condition = %+v, want False/SecretSyncFailed", condition)
			}
			if strings.Contains(condition.Message, sentinel) {
				t.Errorf("condition message %q leaks client error %q", condition.Message, sentinel)
			}

			if desired == nil {
				var absent corev1.Secret
				if err := baseClient.Get(context.Background(), types.NamespacedName{Name: app.EffectiveSecretName(), Namespace: app.Namespace}, &absent); !apierrors.IsNotFound(err) {
					t.Fatalf("failed-created Secret should be absent, got error %v", err)
				}
			} else if !test.staleSecret {
				var current corev1.Secret
				if err := baseClient.Get(context.Background(), client.ObjectKeyFromObject(desired), &current); err != nil {
					t.Fatalf("get desired Secret: %v", err)
				}
				if got, want := relevantSecretState(&current), relevantSecretState(desired); !reflect.DeepEqual(got, want) {
					t.Errorf("desired Secret state = %#v, want unchanged %#v", got, want)
				}
			}
			if stale != nil {
				var current corev1.Secret
				if err := baseClient.Get(context.Background(), client.ObjectKeyFromObject(stale), &current); err != nil {
					t.Fatalf("stale Secret should remain after failed delete: %v", err)
				}
				if got, want := relevantSecretState(&current), relevantSecretState(stale); !reflect.DeepEqual(got, want) {
					t.Errorf("stale Secret state = %#v, want unchanged %#v", got, want)
				}
			}
		})
	}
}

func TestReconcileRenameDoesNotRecoverRawClientSecretFromApplicationSecret(t *testing.T) {
	scheme := newTestScheme()
	omitted := ""
	state := &fakeServerState{clientSecret: &omitted}
	server := fakeAuthentikServer(state, false)
	defer server.Close()

	app := &v1alpha1.OIDCApplication{
		TypeMeta:   metav1.TypeMeta{APIVersion: v1alpha1.GroupVersion.String(), Kind: "OIDCApplication"},
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", UID: "app-uid", Finalizers: []string{finalizerName}},
		Spec: v1alpha1.OIDCApplicationSpec{
			ProviderRef: v1alpha1.ProviderRef{Name: "main"},
			SigningKey:  "Self-signed Certificate",
			Groups:      []v1alpha1.GroupRef{{Name: "admins"}},
			SecretName:  "renamed-credentials",
			SecretTemplate: map[string]string{
				"password": "prefix-{{ .ClientSecret }}",
				"issuer":   "{{ .Issuer }}",
			},
		},
		Status: v1alpha1.OIDCApplicationStatus{SecretName: "legacy-credentials"},
	}
	legacy := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: app.Status.SecretName, Namespace: app.Namespace},
		Data: map[string][]byte{
			"client-secret": []byte("legacy-raw-secret"),
			"issuer":        []byte("stale-issuer"),
		},
	}
	if err := controllerutil.SetControllerReference(app, legacy, scheme); err != nil {
		t.Fatalf("set legacy Secret owner: %v", err)
	}

	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(connectedProvider(server.URL), tokenSecret(), app, legacy).
		WithStatusSubresource(app).
		Build()
	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)})
	if err != nil {
		t.Fatalf("Reconcile should record and requeue the missing dependent entry: %v", err)
	}
	if result.RequeueAfter == 0 {
		t.Error("expected requeue after missing previous rendered entry")
	}

	var absent corev1.Secret
	if err := k8s.Get(context.Background(), types.NamespacedName{Name: app.Spec.SecretName, Namespace: app.Namespace}, &absent); !apierrors.IsNotFound(err) {
		t.Fatalf("renamed application Secret should not be created, got error %v", err)
	}
	var unchanged corev1.Secret
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(legacy), &unchanged); err != nil {
		t.Fatalf("legacy Secret should remain after atomic failure: %v", err)
	}
	if got, want := relevantSecretState(&unchanged), relevantSecretState(legacy); !reflect.DeepEqual(got, want) {
		t.Errorf("legacy Secret state = %#v, want unchanged %#v", got, want)
	}
	var updatedApp v1alpha1.OIDCApplication
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(app), &updatedApp); err != nil {
		t.Fatalf("get app: %v", err)
	}
	condition := meta.FindStatusCondition(updatedApp.Status.Conditions, ConditionReady)
	if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "SecretSyncFailed" {
		t.Fatalf("Ready condition = %+v, want False/SecretSyncFailed", condition)
	}
}

func TestReconcileSecretsRenamePreservesMatchingDependentApplicationKey(t *testing.T) {
	scheme := newTestScheme()
	app := &v1alpha1.OIDCApplication{
		TypeMeta:   metav1.TypeMeta{APIVersion: v1alpha1.GroupVersion.String(), Kind: "OIDCApplication"},
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", UID: "app-uid"},
		Spec: v1alpha1.OIDCApplicationSpec{
			SecretName:     "renamed-credentials",
			SecretTemplate: map[string]string{"password": "prefix-{" + "{ .ClientSecret }}"},
			TargetRefs:     make([]v1alpha1.TargetRef, 1),
		},
		Status: v1alpha1.OIDCApplicationStatus{SecretName: "previous-credentials"},
	}
	previousApplication := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: app.Status.SecretName, Namespace: app.Namespace},
		Data:       map[string][]byte{"password": {0xff, 0x00, 0x7f}},
	}
	envoySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: app.EnvoySecretName(), Namespace: app.Namespace},
		Data:       map[string][]byte{"client-secret": []byte("envoy-only-secret")},
	}
	for _, secret := range []*corev1.Secret{previousApplication, envoySecret} {
		if err := controllerutil.SetControllerReference(app, secret, scheme); err != nil {
			t.Fatalf("set Secret %q owner: %v", secret.Name, err)
		}
	}
	k8s := fake.NewClientBuilder().WithScheme(scheme).WithObjects(previousApplication, envoySecret).Build()
	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}

	_, _, err := reconciler.reconcileSecrets(context.Background(), app, secretTemplateData{})
	if err != nil {
		t.Fatalf("reconcileSecrets() error = %v", err)
	}
	var renamed corev1.Secret
	if err := k8s.Get(context.Background(), types.NamespacedName{Name: app.Spec.SecretName, Namespace: app.Namespace}, &renamed); err != nil {
		t.Fatalf("get renamed application Secret: %v", err)
	}
	if got, want := renamed.Data["password"], previousApplication.Data["password"]; !reflect.DeepEqual(got, want) {
		t.Errorf("dependent entry = %v, want exact previous bytes %v", got, want)
	}
	var deleted corev1.Secret
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(previousApplication), &deleted); !apierrors.IsNotFound(err) {
		t.Fatalf("previous application Secret should be deleted, got error %v", err)
	}
	var preservedEnvoy corev1.Secret
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(envoySecret), &preservedEnvoy); err != nil {
		t.Fatalf("get Envoy Secret: %v", err)
	}
	if got := string(preservedEnvoy.Data["client-secret"]); got != "envoy-only-secret" {
		t.Errorf("Envoy client secret = %q, want envoy-only-secret", got)
	}
}

func TestReconcileSecretsDoesNotSeedEnvoyFromApplicationData(t *testing.T) {
	for name, applicationData := range map[string]map[string][]byte{
		"raw key":      {"client-secret": []byte("application-raw-secret")},
		"static key":   {"static": []byte("application-static-secret")},
		"rendered key": {"password": []byte("prefix-application-rendered-secret")},
	} {
		t.Run(name, func(t *testing.T) {
			scheme := newTestScheme()
			app := &v1alpha1.OIDCApplication{
				TypeMeta:   metav1.TypeMeta{APIVersion: v1alpha1.GroupVersion.String(), Kind: "OIDCApplication"},
				ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", UID: "app-uid"},
				Spec: v1alpha1.OIDCApplicationSpec{
					SecretTemplate: map[string]string{"static": "literal"},
					TargetRefs:     []v1alpha1.TargetRef{{Name: "route"}},
				},
			}
			applicationSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: app.EffectiveSecretName(), Namespace: app.Namespace},
				Data:       applicationData,
			}
			if err := controllerutil.SetControllerReference(app, applicationSecret, scheme); err != nil {
				t.Fatalf("set application Secret owner: %v", err)
			}
			want := relevantSecretState(applicationSecret)
			k8s := fake.NewClientBuilder().WithScheme(scheme).WithObjects(applicationSecret).Build()
			reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}

			_, _, err := reconciler.reconcileSecrets(context.Background(), app, secretTemplateData{})
			if err == nil {
				t.Fatal("reconcileSecrets() error = nil, want unavailable Envoy client secret error")
			}
			var unchanged corev1.Secret
			if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(applicationSecret), &unchanged); err != nil {
				t.Fatalf("get application Secret: %v", err)
			}
			if got := relevantSecretState(&unchanged); !reflect.DeepEqual(got, want) {
				t.Errorf("application Secret state = %#v, want unchanged %#v", got, want)
			}
			var envoy corev1.Secret
			if err := k8s.Get(context.Background(), types.NamespacedName{Name: app.EnvoySecretName(), Namespace: app.Namespace}, &envoy); !apierrors.IsNotFound(err) {
				t.Fatalf("Envoy Secret should not be created, got error %v", err)
			}
		})
	}
}

func TestReconcileSecretsMissingNewDependentApplicationKeyIsAtomic(t *testing.T) {
	scheme := newTestScheme()
	app := &v1alpha1.OIDCApplication{
		TypeMeta:   metav1.TypeMeta{APIVersion: v1alpha1.GroupVersion.String(), Kind: "OIDCApplication"},
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", UID: "app-uid"},
		Spec: v1alpha1.OIDCApplicationSpec{
			SecretTemplate: map[string]string{
				"existing": "existing-{" + "{ .ClientSecret }}",
				"new":      "new-{" + "{ .ClientSecret }}",
			},
			TargetRefs: make([]v1alpha1.TargetRef, 1),
		},
	}
	applicationSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: app.EffectiveSecretName(), Namespace: app.Namespace},
		Data:       map[string][]byte{"existing": {0xff, 0x00, 0x7f}},
	}
	envoySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: app.EnvoySecretName(), Namespace: app.Namespace},
		Data:       map[string][]byte{"client-secret": []byte("envoy-only-secret")},
	}
	for _, secret := range []*corev1.Secret{applicationSecret, envoySecret} {
		if err := controllerutil.SetControllerReference(app, secret, scheme); err != nil {
			t.Fatalf("set Secret %q owner: %v", secret.Name, err)
		}
	}
	wantApplication := relevantSecretState(applicationSecret)
	wantEnvoy := relevantSecretState(envoySecret)
	k8s := fake.NewClientBuilder().WithScheme(scheme).WithObjects(applicationSecret, envoySecret).Build()
	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}

	_, _, err := reconciler.reconcileSecrets(context.Background(), app, secretTemplateData{})
	if err == nil {
		t.Fatal("reconcileSecrets() error = nil, want missing new dependent key error")
	}
	if !strings.Contains(err.Error(), `"new"`) {
		t.Errorf("error %q does not identify new dependent key", err)
	}
	for secret, want := range map[*corev1.Secret]secretRelevantState{
		applicationSecret: wantApplication,
		envoySecret:       wantEnvoy,
	} {
		var unchanged corev1.Secret
		if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(secret), &unchanged); err != nil {
			t.Fatalf("get Secret %q: %v", secret.Name, err)
		}
		if got := relevantSecretState(&unchanged); !reflect.DeepEqual(got, want) {
			t.Errorf("Secret %q state = %#v, want unchanged %#v", secret.Name, got, want)
		}
	}
}

func TestReconcileTemplateRemovalDeletesOwnedApplicationSecretAndClearsStatus(t *testing.T) {
	scheme := newTestScheme()
	state := &fakeServerState{discoveryFailure: true}
	server := fakeAuthentikServer(state, false)
	defer server.Close()

	app := &v1alpha1.OIDCApplication{
		TypeMeta:   metav1.TypeMeta{APIVersion: v1alpha1.GroupVersion.String(), Kind: "OIDCApplication"},
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", UID: "app-uid", Finalizers: []string{finalizerName}},
		Spec: v1alpha1.OIDCApplicationSpec{
			ProviderRef: v1alpha1.ProviderRef{Name: "main"},
			SigningKey:  "Self-signed Certificate",
			TargetRefs:  []v1alpha1.TargetRef{{Name: "my-route"}},
			Groups:      []v1alpha1.GroupRef{{Name: "admins"}},
		},
		Status: v1alpha1.OIDCApplicationStatus{SecretName: "old-application-secret"},
	}
	oldSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: app.Status.SecretName, Namespace: app.Namespace}}
	if err := controllerutil.SetControllerReference(app, oldSecret, scheme); err != nil {
		t.Fatalf("set old Secret owner: %v", err)
	}
	route := &gwapiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "my-route", Namespace: app.Namespace},
		Spec:       gwapiv1.HTTPRouteSpec{Hostnames: []gwapiv1.Hostname{"app.example.com"}},
	}

	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(connectedProvider(server.URL), tokenSecret(), route, app, oldSecret).
		WithStatusSubresource(app).
		Build()
	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	var deleted corev1.Secret
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(oldSecret), &deleted); !apierrors.IsNotFound(err) {
		t.Fatalf("removed application Secret should be deleted, got error %v", err)
	}
	var updatedApp v1alpha1.OIDCApplication
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(app), &updatedApp); err != nil {
		t.Fatalf("get app: %v", err)
	}
	if updatedApp.Status.SecretName != "" {
		t.Errorf("status.secretName = %q, want empty", updatedApp.Status.SecretName)
	}
	var envoySecret corev1.Secret
	if err := k8s.Get(context.Background(), types.NamespacedName{Name: app.EnvoySecretName(), Namespace: app.Namespace}, &envoySecret); err != nil {
		t.Fatalf("get Envoy Secret: %v", err)
	}
	if got := string(envoySecret.Data["client-secret"]); got != "generated-secret" {
		t.Errorf("Envoy client secret = %q, want generated-secret", got)
	}
	var policy egv1alpha1.SecurityPolicy
	if err := k8s.Get(context.Background(), types.NamespacedName{Name: "test-app-my-route", Namespace: app.Namespace}, &policy); err != nil {
		t.Fatalf("get SecurityPolicy: %v", err)
	}
	if got := string(policy.Spec.OIDC.ClientSecret.Name); got != app.EnvoySecretName() {
		t.Errorf("SecurityPolicy client Secret = %q, want %q", got, app.EnvoySecretName())
	}
	condition := meta.FindStatusCondition(updatedApp.Status.Conditions, ConditionReady)
	if condition == nil || condition.Status != metav1.ConditionTrue {
		t.Fatalf("Ready condition = %+v, want True", condition)
	}
}

func TestReconcileDiscoveryFailureWithTemplatePreservesApplicationSecret(t *testing.T) {
	scheme := newTestScheme()
	state := &fakeServerState{discoveryFailure: true}
	server := fakeAuthentikServer(state, false)
	defer server.Close()

	app := &v1alpha1.OIDCApplication{
		TypeMeta:   metav1.TypeMeta{APIVersion: v1alpha1.GroupVersion.String(), Kind: "OIDCApplication"},
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", UID: "app-uid", Finalizers: []string{finalizerName}},
		Spec: v1alpha1.OIDCApplicationSpec{
			ProviderRef:    v1alpha1.ProviderRef{Name: "main"},
			SigningKey:     "Self-signed Certificate",
			Groups:         []v1alpha1.GroupRef{{Name: "admins"}},
			SecretTemplate: map[string]string{"issuer": "{{ .Issuer }}"},
		},
		Status: v1alpha1.OIDCApplicationStatus{SecretName: "test-app-oidc"},
	}
	applicationSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: app.EffectiveSecretName(), Namespace: app.Namespace},
		Data:       map[string][]byte{"issuer": []byte("previous-issuer")},
	}
	if err := controllerutil.SetControllerReference(app, applicationSecret, scheme); err != nil {
		t.Fatalf("set application Secret owner: %v", err)
	}
	wantSecret := relevantSecretState(applicationSecret)

	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(connectedProvider(server.URL), tokenSecret(), app, applicationSecret).
		WithStatusSubresource(app).
		Build()
	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)})
	if err == nil || !strings.Contains(err.Error(), "fetching discovery document") {
		t.Fatalf("Reconcile error = %v, want discovery error", err)
	}
	if result != (ctrl.Result{}) {
		t.Errorf("Reconcile result = %+v, want zero result for error retry", result)
	}

	var unchanged corev1.Secret
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(applicationSecret), &unchanged); err != nil {
		t.Fatalf("get application Secret: %v", err)
	}
	if got := relevantSecretState(&unchanged); !reflect.DeepEqual(got, wantSecret) {
		t.Errorf("application Secret state = %#v, want unchanged %#v", got, wantSecret)
	}
}

func TestReconcileTargetRefsRemovalDeletesOnlyOwnedEnvoySecrets(t *testing.T) {
	scheme := newTestScheme()
	state := &fakeServerState{}
	server := fakeAuthentikServer(state, false)
	defer server.Close()

	app := &v1alpha1.OIDCApplication{
		TypeMeta:   metav1.TypeMeta{APIVersion: v1alpha1.GroupVersion.String(), Kind: "OIDCApplication"},
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", UID: "app-uid", Finalizers: []string{finalizerName}},
		Spec: v1alpha1.OIDCApplicationSpec{
			ProviderRef:    v1alpha1.ProviderRef{Name: "main"},
			SigningKey:     "Self-signed Certificate",
			Groups:         []v1alpha1.GroupRef{{Name: "admins"}},
			SecretTemplate: map[string]string{"issuer": "{{ .Issuer }}"},
		},
		Status: v1alpha1.OIDCApplicationStatus{SecretName: "test-app-oidc"},
	}
	applicationSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: app.EffectiveSecretName(), Namespace: app.Namespace}}
	ownedEnvoy := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: app.EnvoySecretName(), Namespace: app.Namespace}}
	foreignEnvoy := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "foreign-envoy-secret", Namespace: app.Namespace, Labels: map[string]string{secretRoleLabel: secretRoleEnvoy}},
		Data:       map[string][]byte{"client-secret": []byte("foreign-secret")},
	}
	for _, secret := range []*corev1.Secret{applicationSecret, ownedEnvoy} {
		if err := controllerutil.SetControllerReference(app, secret, scheme); err != nil {
			t.Fatalf("set Secret %q owner: %v", secret.Name, err)
		}
	}

	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(connectedProvider(server.URL), tokenSecret(), app, applicationSecret, ownedEnvoy, foreignEnvoy).
		WithStatusSubresource(app).
		Build()
	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	var deleted corev1.Secret
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(ownedEnvoy), &deleted); !apierrors.IsNotFound(err) {
		t.Fatalf("owned Envoy Secret should be deleted, got error %v", err)
	}
	for _, preserved := range []*corev1.Secret{applicationSecret, foreignEnvoy} {
		var current corev1.Secret
		if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(preserved), &current); err != nil {
			t.Errorf("Secret %q should remain: %v", preserved.Name, err)
		}
	}
}

func TestReconcileTargetRefsRemovalPreservesFixedUnownedEnvoySecret(t *testing.T) {
	scheme := newTestScheme()
	state := &fakeServerState{}
	server := fakeAuthentikServer(state, false)
	defer server.Close()

	app := &v1alpha1.OIDCApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", UID: "app-uid", Finalizers: []string{finalizerName}},
		Spec: v1alpha1.OIDCApplicationSpec{
			ProviderRef: v1alpha1.ProviderRef{Name: "main"},
			SigningKey:  "Self-signed Certificate",
			Groups:      []v1alpha1.GroupRef{{Name: "admins"}},
		},
	}
	unownedEnvoy := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        app.EnvoySecretName(),
			Namespace:   app.Namespace,
			Labels:      map[string]string{secretRoleLabel: secretRoleEnvoy, "foreign": "label"},
			Annotations: map[string]string{"foreign": "annotation"},
		},
		Data: map[string][]byte{"client-secret": []byte("foreign-secret")},
		Type: corev1.SecretTypeTLS,
	}
	want := relevantSecretState(unownedEnvoy)
	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(connectedProvider(server.URL), tokenSecret(), app, unownedEnvoy).
		WithStatusSubresource(app).
		Build()
	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	var preserved corev1.Secret
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(unownedEnvoy), &preserved); err != nil {
		t.Fatalf("fixed unowned Envoy Secret should remain: %v", err)
	}
	if got := relevantSecretState(&preserved); !reflect.DeepEqual(got, want) {
		t.Errorf("fixed unowned Envoy Secret state = %#v, want unchanged %#v", got, want)
	}
}

func TestReconcileSecretsRejectsDesiredNameCollisionAtomically(t *testing.T) {
	scheme := newTestScheme()
	app := &v1alpha1.OIDCApplication{
		TypeMeta:   metav1.TypeMeta{APIVersion: v1alpha1.GroupVersion.String(), Kind: "OIDCApplication"},
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", UID: "app-uid"},
		Spec: v1alpha1.OIDCApplicationSpec{
			SecretName:     "test-app-envoy-oidc",
			SecretTemplate: map[string]string{"value": "new-value"},
			TargetRefs:     []v1alpha1.TargetRef{{Name: "route"}},
		},
	}
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        app.EnvoySecretName(),
			Namespace:   app.Namespace,
			Labels:      map[string]string{"existing": "label"},
			Annotations: map[string]string{"existing": "annotation"},
		},
		Data: map[string][]byte{"value": []byte("unchanged")},
		Type: corev1.SecretTypeTLS,
	}
	if err := controllerutil.SetControllerReference(app, existing, scheme); err != nil {
		t.Fatalf("set existing Secret owner: %v", err)
	}
	k8s := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()
	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
	want := relevantSecretState(existing)

	_, _, err := reconciler.reconcileSecrets(context.Background(), app, secretTemplateData{ClientSecret: "new-secret"})
	if err == nil {
		t.Fatal("reconcileSecrets() error = nil, want desired name collision error")
	}
	if !strings.Contains(err.Error(), app.EnvoySecretName()) {
		t.Errorf("collision error %q does not identify the shared Secret name", err)
	}
	var unchanged corev1.Secret
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(existing), &unchanged); err != nil {
		t.Fatalf("get existing Secret: %v", err)
	}
	if got := relevantSecretState(&unchanged); !reflect.DeepEqual(got, want) {
		t.Errorf("colliding Secret state = %#v, want unchanged %#v", got, want)
	}
}

func TestReconcileEnvoyOwnershipCollisionDoesNotMutateApplicationSecret(t *testing.T) {
	scheme := newTestScheme()
	state := &fakeServerState{}
	server := fakeAuthentikServer(state, false)
	defer server.Close()

	route := &gwapiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "my-route", Namespace: "test-ns"},
		Spec:       gwapiv1.HTTPRouteSpec{Hostnames: []gwapiv1.Hostname{"app.example.com"}},
	}
	app := &v1alpha1.OIDCApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", UID: "app-uid", Finalizers: []string{finalizerName}},
		Spec: v1alpha1.OIDCApplicationSpec{
			ProviderRef:    v1alpha1.ProviderRef{Name: "main"},
			SigningKey:     "Self-signed Certificate",
			Groups:         []v1alpha1.GroupRef{{Name: "admins"}},
			TargetRefs:     []v1alpha1.TargetRef{{Name: "my-route"}},
			SecretTemplate: map[string]string{"value": "new-value"},
		},
	}
	controlled := true
	foreignEnvoy := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        app.EnvoySecretName(),
			Namespace:   app.Namespace,
			Labels:      map[string]string{"foreign": "label"},
			Annotations: map[string]string{"foreign": "annotation"},
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "Deployment", Name: "other", UID: "other-uid", Controller: &controlled},
			},
		},
		Data: map[string][]byte{"client-secret": []byte("foreign-value")},
		Type: corev1.SecretTypeTLS,
	}
	wantForeign := relevantSecretState(foreignEnvoy)
	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(connectedProvider(server.URL), tokenSecret(), route, app, foreignEnvoy).
		WithStatusSubresource(app).
		Build()
	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)})
	if err != nil {
		t.Fatalf("Reconcile should record and requeue the Secret error: %v", err)
	}
	if result.RequeueAfter == 0 {
		t.Error("expected requeue after Secret ownership collision")
	}

	var updatedApp v1alpha1.OIDCApplication
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(app), &updatedApp); err != nil {
		t.Fatalf("get app: %v", err)
	}
	condition := meta.FindStatusCondition(updatedApp.Status.Conditions, ConditionReady)
	if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "SecretSyncFailed" {
		t.Fatalf("Ready condition = %+v, want False/SecretSyncFailed", condition)
	}
	var applicationSecret corev1.Secret
	if err := k8s.Get(context.Background(), types.NamespacedName{Name: app.EffectiveSecretName(), Namespace: app.Namespace}, &applicationSecret); !apierrors.IsNotFound(err) {
		t.Fatalf("application Secret should not be created, got error %v", err)
	}
	var unchangedEnvoy corev1.Secret
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(foreignEnvoy), &unchangedEnvoy); err != nil {
		t.Fatalf("get foreign Envoy Secret: %v", err)
	}
	if got := relevantSecretState(&unchangedEnvoy); !reflect.DeepEqual(got, wantForeign) {
		t.Errorf("foreign Envoy Secret state = %#v, want unchanged %#v", got, wantForeign)
	}
}

func TestReconcileApplicationOwnershipCollisionPreservesForeignSecret(t *testing.T) {
	scheme := newTestScheme()
	state := &fakeServerState{}
	server := fakeAuthentikServer(state, false)
	defer server.Close()

	app := &v1alpha1.OIDCApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", UID: "app-uid", Finalizers: []string{finalizerName}},
		Spec: v1alpha1.OIDCApplicationSpec{
			ProviderRef:    v1alpha1.ProviderRef{Name: "main"},
			SigningKey:     "Self-signed Certificate",
			Groups:         []v1alpha1.GroupRef{{Name: "admins"}},
			SecretTemplate: map[string]string{"value": "new-value"},
		},
	}
	controlled := true
	foreign := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        app.EffectiveSecretName(),
			Namespace:   app.Namespace,
			Labels:      map[string]string{"foreign": "label"},
			Annotations: map[string]string{"foreign": "annotation"},
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "Deployment", Name: "other", UID: "other-uid", Controller: &controlled},
			},
		},
		Data: map[string][]byte{"value": []byte("foreign-value")},
		Type: corev1.SecretTypeTLS,
	}
	wantForeign := relevantSecretState(foreign)
	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(connectedProvider(server.URL), tokenSecret(), app, foreign).
		WithStatusSubresource(app).
		Build()
	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)})
	if err != nil {
		t.Fatalf("Reconcile should record and requeue the Secret error: %v", err)
	}
	if result.RequeueAfter == 0 {
		t.Error("expected requeue after application Secret ownership collision")
	}

	var updatedApp v1alpha1.OIDCApplication
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(app), &updatedApp); err != nil {
		t.Fatalf("get app: %v", err)
	}
	condition := meta.FindStatusCondition(updatedApp.Status.Conditions, ConditionReady)
	if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "SecretSyncFailed" {
		t.Fatalf("Ready condition = %+v, want False/SecretSyncFailed", condition)
	}
	var preserved corev1.Secret
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(foreign), &preserved); err != nil {
		t.Fatalf("get foreign application Secret: %v", err)
	}
	if got := relevantSecretState(&preserved); !reflect.DeepEqual(got, wantForeign) {
		t.Errorf("foreign application Secret state = %#v, want unchanged %#v", got, wantForeign)
	}
}

func TestReconcileNameOverlapTransitionKeepsDesiredEnvoySecret(t *testing.T) {
	scheme := newTestScheme()
	state := &fakeServerState{}
	server := fakeAuthentikServer(state, false)
	defer server.Close()

	route := &gwapiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "my-route", Namespace: "test-ns"},
		Spec:       gwapiv1.HTTPRouteSpec{Hostnames: []gwapiv1.Hostname{"app.example.com"}},
	}
	app := &v1alpha1.OIDCApplication{
		TypeMeta:   metav1.TypeMeta{APIVersion: v1alpha1.GroupVersion.String(), Kind: "OIDCApplication"},
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", UID: "app-uid", Finalizers: []string{finalizerName}},
		Spec: v1alpha1.OIDCApplicationSpec{
			ProviderRef: v1alpha1.ProviderRef{Name: "main"},
			SigningKey:  "Self-signed Certificate",
			Groups:      []v1alpha1.GroupRef{{Name: "admins"}},
			TargetRefs:  []v1alpha1.TargetRef{{Name: "my-route"}},
		},
		Status: v1alpha1.OIDCApplicationStatus{SecretName: "test-app-envoy-oidc"},
	}
	priorApplication := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      app.EnvoySecretName(),
			Namespace: app.Namespace,
			Labels:    map[string]string{secretRoleLabel: secretRoleApplication},
		},
		Data: map[string][]byte{"legacy": []byte("old-value")},
	}
	if err := controllerutil.SetControllerReference(app, priorApplication, scheme); err != nil {
		t.Fatalf("set prior Secret owner: %v", err)
	}
	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(connectedProvider(server.URL), tokenSecret(), route, app, priorApplication).
		WithStatusSubresource(app).
		Build()
	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	var envoySecret corev1.Secret
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(priorApplication), &envoySecret); err != nil {
		t.Fatalf("desired Envoy Secret was deleted: %v", err)
	}
	if want := map[string][]byte{"client-secret": []byte("generated-secret")}; !reflect.DeepEqual(envoySecret.Data, want) {
		t.Errorf("Envoy Secret data = %#v, want %#v", envoySecret.Data, want)
	}
	if got := envoySecret.Labels[secretRoleLabel]; got != secretRoleEnvoy {
		t.Errorf("transitioned Secret role label = %q, want %q", got, secretRoleEnvoy)
	}
	var policy egv1alpha1.SecurityPolicy
	if err := k8s.Get(context.Background(), types.NamespacedName{Name: "test-app-my-route", Namespace: app.Namespace}, &policy); err != nil {
		t.Fatalf("get SecurityPolicy: %v", err)
	}
	if got := string(policy.Spec.OIDC.ClientSecret.Name); got != app.EnvoySecretName() {
		t.Errorf("SecurityPolicy Secret = %q, want %q", got, app.EnvoySecretName())
	}
	var updatedApp v1alpha1.OIDCApplication
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(app), &updatedApp); err != nil {
		t.Fatalf("get app: %v", err)
	}
	if updatedApp.Status.SecretName != "" {
		t.Errorf("status.secretName = %q, want empty", updatedApp.Status.SecretName)
	}
}

func TestReconcileDoesNotTrustForeignStatusSecretData(t *testing.T) {
	scheme := newTestScheme()
	omitted := ""
	state := &fakeServerState{clientSecret: &omitted}
	server := fakeAuthentikServer(state, false)
	defer server.Close()

	route := &gwapiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "my-route", Namespace: "test-ns"},
		Spec:       gwapiv1.HTTPRouteSpec{Hostnames: []gwapiv1.Hostname{"app.example.com"}},
	}
	app := &v1alpha1.OIDCApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", UID: "app-uid", Finalizers: []string{finalizerName}},
		Spec: v1alpha1.OIDCApplicationSpec{
			ProviderRef:    v1alpha1.ProviderRef{Name: "main"},
			SigningKey:     "Self-signed Certificate",
			Groups:         []v1alpha1.GroupRef{{Name: "admins"}},
			TargetRefs:     []v1alpha1.TargetRef{{Name: "my-route"}},
			SecretName:     "new-application-secret",
			SecretTemplate: map[string]string{"password": "{{ .ClientSecret }}"},
		},
		Status: v1alpha1.OIDCApplicationStatus{SecretName: "foreign-legacy-secret"},
	}
	controlled := true
	foreignLegacy := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      app.Status.SecretName,
			Namespace: app.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "Deployment", Name: "other", UID: "other-uid", Controller: &controlled},
			},
		},
		Data: map[string][]byte{"client-secret": []byte("foreign-credential"), "password": []byte("foreign-rendered")},
	}
	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(connectedProvider(server.URL), tokenSecret(), route, app, foreignLegacy).
		WithStatusSubresource(app).
		Build()
	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)})
	if err != nil {
		t.Fatalf("Reconcile should record and requeue the Secret error: %v", err)
	}
	if result.RequeueAfter == 0 {
		t.Error("expected requeue after missing trusted client secret")
	}

	var updatedApp v1alpha1.OIDCApplication
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(app), &updatedApp); err != nil {
		t.Fatalf("get app: %v", err)
	}
	condition := meta.FindStatusCondition(updatedApp.Status.Conditions, ConditionReady)
	if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "SecretSyncFailed" {
		t.Fatalf("Ready condition = %+v, want False/SecretSyncFailed", condition)
	}
	for _, name := range []string{app.EffectiveSecretName(), app.EnvoySecretName()} {
		var destination corev1.Secret
		if err := k8s.Get(context.Background(), types.NamespacedName{Name: name, Namespace: app.Namespace}, &destination); !apierrors.IsNotFound(err) {
			t.Fatalf("destination Secret %q should not exist, got error %v", name, err)
		}
	}
	var unchanged corev1.Secret
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(foreignLegacy), &unchanged); err != nil {
		t.Fatalf("get foreign legacy Secret: %v", err)
	}
	if got, want := relevantSecretState(&unchanged), relevantSecretState(foreignLegacy); !reflect.DeepEqual(got, want) {
		t.Errorf("foreign legacy Secret state = %#v, want unchanged %#v", got, want)
	}
}

func TestReconcileRenamePreservesForeignStatusSecret(t *testing.T) {
	scheme := newTestScheme()
	state := &fakeServerState{}
	server := fakeAuthentikServer(state, false)
	defer server.Close()

	app := &v1alpha1.OIDCApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", UID: "app-uid", Finalizers: []string{finalizerName}},
		Spec: v1alpha1.OIDCApplicationSpec{
			ProviderRef:    v1alpha1.ProviderRef{Name: "main"},
			SigningKey:     "Self-signed Certificate",
			Groups:         []v1alpha1.GroupRef{{Name: "admins"}},
			SecretName:     "new-application-secret",
			SecretTemplate: map[string]string{"password": "{{ .ClientSecret }}"},
		},
		Status: v1alpha1.OIDCApplicationStatus{SecretName: "foreign-old-secret"},
	}
	foreignOld := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        app.Status.SecretName,
			Namespace:   app.Namespace,
			Labels:      map[string]string{"foreign": "label"},
			Annotations: map[string]string{"foreign": "annotation"},
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "Deployment", Name: "other", UID: "other-uid"},
			},
		},
		Data: map[string][]byte{"password": []byte("foreign-value")},
		Type: corev1.SecretTypeTLS,
	}
	wantForeign := relevantSecretState(foreignOld)
	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(connectedProvider(server.URL), tokenSecret(), app, foreignOld).
		WithStatusSubresource(app).
		Build()
	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(app)}); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	var desired corev1.Secret
	if err := k8s.Get(context.Background(), types.NamespacedName{Name: app.Spec.SecretName, Namespace: app.Namespace}, &desired); err != nil {
		t.Fatalf("get desired application Secret: %v", err)
	}
	if got := string(desired.Data["password"]); got != "generated-secret" {
		t.Errorf("desired application Secret password = %q, want generated-secret", got)
	}
	var preserved corev1.Secret
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(foreignOld), &preserved); err != nil {
		t.Fatalf("foreign old Secret should remain: %v", err)
	}
	if got := relevantSecretState(&preserved); !reflect.DeepEqual(got, wantForeign) {
		t.Errorf("foreign old Secret state = %#v, want unchanged %#v", got, wantForeign)
	}
	var updatedApp v1alpha1.OIDCApplication
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(app), &updatedApp); err != nil {
		t.Fatalf("get app: %v", err)
	}
	if updatedApp.Status.SecretName != app.Spec.SecretName {
		t.Errorf("status.secretName = %q, want %q", updatedApp.Status.SecretName, app.Spec.SecretName)
	}
}

func TestReconcileSecretsDeletesOnlyTrackedOrRoleLabeledApplicationSecrets(t *testing.T) {
	scheme := newTestScheme()
	app := &v1alpha1.OIDCApplication{
		TypeMeta:   metav1.TypeMeta{APIVersion: v1alpha1.GroupVersion.String(), Kind: "OIDCApplication"},
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", UID: "app-uid"},
		Spec: v1alpha1.OIDCApplicationSpec{
			SecretName:     "desired-secret",
			SecretTemplate: map[string]string{"value": "current"},
			TargetRefs:     []v1alpha1.TargetRef{{Name: "route"}},
		},
		Status: v1alpha1.OIDCApplicationStatus{SecretName: "old-secret"},
	}
	otherApp := &v1alpha1.OIDCApplication{
		TypeMeta:   metav1.TypeMeta{APIVersion: v1alpha1.GroupVersion.String(), Kind: "OIDCApplication"},
		ObjectMeta: metav1.ObjectMeta{Name: "other-app", Namespace: app.Namespace, UID: "other-app-uid"},
	}
	ownedSecret := func(name string, labels map[string]string) *corev1.Secret {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: app.Namespace, Labels: labels},
			Data:       map[string][]byte{"value": []byte("stale")},
		}
		if err := controllerutil.SetControllerReference(app, secret, scheme); err != nil {
			t.Fatalf("set Secret %q owner: %v", name, err)
		}
		return secret
	}
	oldSecret := ownedSecret("old-secret", map[string]string{secretRoleLabel: secretRoleApplication})
	labeledIntermediate := ownedSecret("labeled-intermediate-secret", map[string]string{secretRoleLabel: secretRoleApplication})
	unlabeledIntermediate := ownedSecret("unlabeled-intermediate-secret", nil)
	mislabeledIntermediate := ownedSecret("mislabeled-intermediate-secret", map[string]string{secretRoleLabel: "changed"})
	unownedSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "unowned-secret", Namespace: app.Namespace, Labels: map[string]string{secretRoleLabel: secretRoleApplication}},
	}
	otherOwnedSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "other-app-secret", Namespace: app.Namespace, Labels: map[string]string{secretRoleLabel: secretRoleApplication}},
		Data:       map[string][]byte{"value": []byte("other")},
	}
	if err := controllerutil.SetControllerReference(otherApp, otherOwnedSecret, scheme); err != nil {
		t.Fatalf("set other Secret owner: %v", err)
	}
	k8s := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		oldSecret,
		labeledIntermediate,
		unlabeledIntermediate,
		mislabeledIntermediate,
		unownedSecret,
		otherOwnedSecret,
	).Build()
	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
	applicationName, envoyName, err := reconciler.reconcileSecrets(context.Background(), app, secretTemplateData{ClientSecret: "client-secret"})
	if err != nil {
		t.Fatalf("reconcileSecrets() error = %v", err)
	}
	if applicationName != app.Spec.SecretName || envoyName != app.EnvoySecretName() {
		t.Errorf("reconcileSecrets() names = %q, %q", applicationName, envoyName)
	}

	for name, role := range map[string]string{
		applicationName: secretRoleApplication,
		envoyName:       secretRoleEnvoy,
	} {
		var desired corev1.Secret
		if err := k8s.Get(context.Background(), types.NamespacedName{Name: name, Namespace: app.Namespace}, &desired); err != nil {
			t.Errorf("get desired Secret %q: %v", name, err)
			continue
		}
		if got := desired.Labels[secretRoleLabel]; got != role {
			t.Errorf("desired Secret %q role label = %q, want %q", name, got, role)
		}
	}
	for _, stale := range []*corev1.Secret{oldSecret, labeledIntermediate} {
		var deleted corev1.Secret
		if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(stale), &deleted); !apierrors.IsNotFound(err) {
			t.Errorf("owned stale Secret %q should be deleted, got error %v", stale.Name, err)
		}
	}
	for _, secret := range []*corev1.Secret{unlabeledIntermediate, mislabeledIntermediate, unownedSecret, otherOwnedSecret} {
		var preserved corev1.Secret
		if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(secret), &preserved); err != nil {
			t.Errorf("non-owned Secret %q was deleted: %v", secret.Name, err)
		}
	}
}

func TestReconcileDoesNotTrustUnownedDesiredApplicationSecretData(t *testing.T) {
	scheme := newTestScheme()
	app := &v1alpha1.OIDCApplication{
		TypeMeta:   metav1.TypeMeta{APIVersion: v1alpha1.GroupVersion.String(), Kind: "OIDCApplication"},
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", UID: "app-uid"},
		Spec: v1alpha1.OIDCApplicationSpec{
			SecretTemplate: map[string]string{"password": "{" + "{ .ClientSecret }}"},
		},
	}
	unowned := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        app.EffectiveSecretName(),
			Namespace:   app.Namespace,
			Labels:      map[string]string{"foreign": "label"},
			Annotations: map[string]string{"foreign": "annotation"},
		},
		Data: map[string][]byte{"password": []byte("untrusted-value"), "client-secret": []byte("untrusted-credential")},
		Type: corev1.SecretTypeTLS,
	}
	want := relevantSecretState(unowned)
	k8s := fake.NewClientBuilder().WithScheme(scheme).WithObjects(unowned).Build()
	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
	_, _, err := reconciler.reconcileSecrets(context.Background(), app, secretTemplateData{})
	if err == nil {
		t.Fatal("reconcileSecrets() error = nil, want missing trusted previous value error")
	}
	var unchanged corev1.Secret
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(unowned), &unchanged); err != nil {
		t.Fatalf("get unowned desired Secret: %v", err)
	}
	if got := relevantSecretState(&unchanged); !reflect.DeepEqual(got, want) {
		t.Errorf("unowned desired Secret state = %#v, want unchanged %#v", got, want)
	}
}

func TestDeleteStaleSecretsUsesFreshUIDAndResourceVersionPreconditions(t *testing.T) {
	scheme := newTestScheme()
	app := &v1alpha1.OIDCApplication{
		TypeMeta:   metav1.TypeMeta{APIVersion: v1alpha1.GroupVersion.String(), Kind: "OIDCApplication"},
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", UID: "app-uid"},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "stale-secret", Namespace: app.Namespace, UID: "secret-uid", ResourceVersion: "7", Labels: map[string]string{secretRoleLabel: secretRoleApplication}},
	}
	if err := controllerutil.SetControllerReference(app, secret, scheme); err != nil {
		t.Fatalf("set Secret owner: %v", err)
	}
	baseClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	freshUID := types.UID("fresh-secret-uid")
	freshResourceVersion := "8"
	var deleteOptions client.DeleteOptions
	intercepted := interceptor.NewClient(baseClient, interceptor.Funcs{
		Get: func(ctx context.Context, delegate client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if err := delegate.Get(ctx, key, obj, opts...); err != nil {
				return err
			}
			obj.SetUID(freshUID)
			obj.SetResourceVersion(freshResourceVersion)
			return nil
		},
		Delete: func(_ context.Context, _ client.WithWatch, _ client.Object, opts ...client.DeleteOption) error {
			deleteOptions.ApplyOptions(opts)
			return nil
		},
	})
	reconciler := &OIDCApplicationReconciler{Client: intercepted, Scheme: scheme}
	if err := reconciler.deleteStaleSecrets(context.Background(), app, func(string) bool { return false }); err != nil {
		t.Fatalf("deleteStaleSecrets() error = %v", err)
	}
	if deleteOptions.Preconditions == nil || deleteOptions.Preconditions.UID == nil || *deleteOptions.Preconditions.UID != freshUID {
		t.Errorf("delete UID precondition = %+v, want %q", deleteOptions.Preconditions, freshUID)
	}
	if deleteOptions.Preconditions == nil || deleteOptions.Preconditions.ResourceVersion == nil || *deleteOptions.Preconditions.ResourceVersion != freshResourceVersion {
		t.Errorf("delete resource version precondition = %+v, want %q", deleteOptions.Preconditions, freshResourceVersion)
	}
}

func TestDeleteStaleSecretsRechecksOwnershipAfterList(t *testing.T) {
	scheme := newTestScheme()
	app := &v1alpha1.OIDCApplication{
		TypeMeta:   metav1.TypeMeta{APIVersion: v1alpha1.GroupVersion.String(), Kind: "OIDCApplication"},
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", UID: "app-uid"},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "stale-secret", Namespace: app.Namespace, UID: "secret-uid", ResourceVersion: "7", Labels: map[string]string{secretRoleLabel: secretRoleApplication}},
	}
	if err := controllerutil.SetControllerReference(app, secret, scheme); err != nil {
		t.Fatalf("set Secret owner: %v", err)
	}
	baseClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	deleteCalled := false
	getCalled := false
	intercepted := interceptor.NewClient(baseClient, interceptor.Funcs{
		Get: func(ctx context.Context, delegate client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if key != client.ObjectKeyFromObject(secret) {
				return delegate.Get(ctx, key, obj, opts...)
			}
			getCalled = true
			current := secret.DeepCopy()
			controlled := true
			current.OwnerReferences = []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "Deployment", Name: "other", UID: "other-uid", Controller: &controlled},
			}
			current.DeepCopyInto(obj.(*corev1.Secret))
			return nil
		},
		Delete: func(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error {
			deleteCalled = true
			return nil
		},
	})
	reconciler := &OIDCApplicationReconciler{Client: intercepted, Scheme: scheme}
	if err := reconciler.deleteStaleSecrets(context.Background(), app, func(string) bool { return false }); err != nil {
		t.Fatalf("deleteStaleSecrets() error = %v", err)
	}
	if !getCalled {
		t.Error("expected fresh Get before stale Secret deletion")
	}
	if deleteCalled {
		t.Error("Secret was deleted after its controller ownership changed")
	}
}

func TestDeleteStaleSecretsRechecksApplicationRoleAfterList(t *testing.T) {
	scheme := newTestScheme()
	app := &v1alpha1.OIDCApplication{
		TypeMeta:   metav1.TypeMeta{APIVersion: v1alpha1.GroupVersion.String(), Kind: "OIDCApplication"},
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", UID: "app-uid"},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "stale-secret", Namespace: app.Namespace, Labels: map[string]string{secretRoleLabel: secretRoleApplication}},
	}
	if err := controllerutil.SetControllerReference(app, secret, scheme); err != nil {
		t.Fatalf("set Secret owner: %v", err)
	}
	baseClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	deleteCalled := false
	intercepted := interceptor.NewClient(baseClient, interceptor.Funcs{
		Get: func(ctx context.Context, delegate client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if key != client.ObjectKeyFromObject(secret) {
				return delegate.Get(ctx, key, obj, opts...)
			}
			current := secret.DeepCopy()
			current.Labels[secretRoleLabel] = "mutated"
			current.DeepCopyInto(obj.(*corev1.Secret))
			return nil
		},
		Delete: func(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error {
			deleteCalled = true
			return nil
		},
	})
	reconciler := &OIDCApplicationReconciler{Client: intercepted, Scheme: scheme}
	if err := reconciler.deleteStaleSecrets(context.Background(), app, func(string) bool { return false }); err != nil {
		t.Fatalf("deleteStaleSecrets() error = %v", err)
	}
	if deleteCalled {
		t.Error("Secret was deleted after its application role label changed")
	}
}

func TestReconcileSecretsRejectsAnotherController(t *testing.T) {
	scheme := newTestScheme()
	app := &v1alpha1.OIDCApplication{
		TypeMeta:   metav1.TypeMeta{APIVersion: v1alpha1.GroupVersion.String(), Kind: "OIDCApplication"},
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", UID: "app-uid"},
		Spec: v1alpha1.OIDCApplicationSpec{
			SecretTemplate: map[string]string{"value": "new-value"},
		},
	}
	controlled := true
	colliding := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        app.EffectiveSecretName(),
			Namespace:   app.Namespace,
			Labels:      map[string]string{"foreign": "label"},
			Annotations: map[string]string{"foreign": "annotation"},
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "Deployment", Name: "other", UID: "other-uid", Controller: &controlled},
			},
		},
		Data: map[string][]byte{"value": []byte("unchanged")},
		Type: corev1.SecretTypeTLS,
	}
	want := relevantSecretState(colliding)
	k8s := fake.NewClientBuilder().WithScheme(scheme).WithObjects(colliding).Build()
	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
	_, _, err := reconciler.reconcileSecrets(context.Background(), app, secretTemplateData{})
	if err == nil {
		t.Fatal("reconcileSecrets() error = nil, want controller collision error")
	}
	if !strings.Contains(err.Error(), app.EffectiveSecretName()) || strings.Contains(err.Error(), "unchanged") {
		t.Errorf("collision error should name the Secret without its data: %v", err)
	}
	var unchanged corev1.Secret
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(colliding), &unchanged); err != nil {
		t.Fatalf("get colliding Secret: %v", err)
	}
	if got := relevantSecretState(&unchanged); !reflect.DeepEqual(got, want) {
		t.Errorf("colliding Secret state = %#v, want unchanged %#v", got, want)
	}
}

func TestReconcileAdoptsExistingApp(t *testing.T) {
	scheme := newTestScheme()
	state := &fakeServerState{}
	server := fakeAuthentikServer(state, true)
	defer server.Close()

	app := &v1alpha1.OIDCApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", Finalizers: []string{finalizerName}},
		Spec: v1alpha1.OIDCApplicationSpec{
			ProviderRef:      v1alpha1.ProviderRef{Name: "main"},
			SigningKey:       "Self-signed Certificate",
			PropertyMappings: []string{"openid"},
			Groups:           []v1alpha1.GroupRef{{Name: "admins"}},
		},
	}

	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(connectedProvider(server.URL), tokenSecret(), app).
		WithStatusSubresource(app).
		Build()

	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-app", Namespace: "test-ns"},
	}); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	if state.providerPost {
		t.Error("expected NO POST to /providers/oauth2/ when adopting an existing app")
	}
	if state.appPost {
		t.Error("expected NO POST to /core/applications/ when adopting an existing app")
	}

	var updated v1alpha1.OIDCApplication
	if err := k8s.Get(context.Background(), types.NamespacedName{Name: "test-app", Namespace: "test-ns"}, &updated); err != nil {
		t.Fatalf("get app: %v", err)
	}
	if updated.Status.Authentik == nil || updated.Status.Authentik.ProviderID != 7 {
		t.Errorf("expected adopted providerID 7, got %+v", updated.Status.Authentik)
	}
	if updated.Status.Authentik.ApplicationID != "existing-app-uuid" {
		t.Errorf("expected adopted applicationID existing-app-uuid, got %s", updated.Status.Authentik.ApplicationID)
	}
}

func TestReconcileProviderNotConnected(t *testing.T) {
	scheme := newTestScheme()

	provider := &v1alpha1.AuthentikProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "main"},
		Spec: v1alpha1.AuthentikProviderSpec{
			Host:              "https://authentik.example.com",
			APITokenSecretRef: v1alpha1.SecretKeyReference{Name: "auth-token", Namespace: "default", Key: "token"},
		},
		Status: v1alpha1.AuthentikProviderStatus{
			Conditions: []metav1.Condition{
				{Type: ConditionConnected, Status: metav1.ConditionFalse, LastTransitionTime: metav1.Now(), Reason: "Down"},
			},
		},
	}

	app := &v1alpha1.OIDCApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", Finalizers: []string{finalizerName}},
		Spec: v1alpha1.OIDCApplicationSpec{
			ProviderRef: v1alpha1.ProviderRef{Name: "main"},
			SigningKey:  "key",
			Groups:      []v1alpha1.GroupRef{{Name: "admins"}},
		},
	}

	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(provider, app).
		WithStatusSubresource(app).
		Build()

	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-app", Namespace: "test-ns"},
	})
	if err != nil {
		t.Fatalf("Reconcile should requeue, not error: %v", err)
	}
	if result.RequeueAfter == 0 {
		t.Error("expected requeue when provider not connected")
	}

	var updated v1alpha1.OIDCApplication
	if err := k8s.Get(context.Background(), types.NamespacedName{Name: "test-app", Namespace: "test-ns"}, &updated); err != nil {
		t.Fatalf("get app: %v", err)
	}
	if len(updated.Status.Conditions) == 0 || updated.Status.Conditions[0].Reason != "ProviderNotConnected" {
		t.Errorf("expected ProviderNotConnected condition, got %+v", updated.Status.Conditions)
	}
}

func TestOIDCApplicationReconcileProviderNotFound(t *testing.T) {
	scheme := newTestScheme()

	app := &v1alpha1.OIDCApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "default", Finalizers: []string{finalizerName}},
		Spec: v1alpha1.OIDCApplicationSpec{
			ProviderRef: v1alpha1.ProviderRef{Name: "nonexistent-provider"},
			SigningKey:  "key",
			Groups:      []v1alpha1.GroupRef{{Name: "admins"}},
		},
	}

	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(app).
		WithStatusSubresource(app).
		Build()

	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-app", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile should requeue, not error: %v", err)
	}
	if result.RequeueAfter == 0 {
		t.Error("expected requeue when provider not found")
	}

	var updated v1alpha1.OIDCApplication
	if err := k8s.Get(context.Background(), types.NamespacedName{Name: "test-app", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("get app: %v", err)
	}
	if len(updated.Status.Conditions) == 0 || updated.Status.Conditions[0].Reason != "ProviderNotFound" {
		t.Errorf("expected ProviderNotFound condition, got %+v", updated.Status.Conditions)
	}
}

func TestOIDCApplicationReconcileAddsFinalizer(t *testing.T) {
	scheme := newTestScheme()

	app := &v1alpha1.OIDCApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "default"},
		Spec: v1alpha1.OIDCApplicationSpec{
			ProviderRef: v1alpha1.ProviderRef{Name: "main"},
			SigningKey:  "key",
			Groups:      []v1alpha1.GroupRef{{Name: "admins"}},
		},
	}

	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(app).
		WithStatusSubresource(app).
		Build()

	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-app", Namespace: "default"},
	}); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	var updated v1alpha1.OIDCApplication
	if err := k8s.Get(context.Background(), types.NamespacedName{Name: "test-app", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("get app: %v", err)
	}
	found := false
	for _, f := range updated.Finalizers {
		if f == finalizerName {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finalizer to be added")
	}
}

func TestOIDCApplicationReconcileNotFound(t *testing.T) {
	scheme := newTestScheme()
	k8s := fake.NewClientBuilder().WithScheme(scheme).Build()
	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "nonexistent", Namespace: "default"},
	}); err != nil {
		t.Fatalf("Reconcile should not error for not-found resource: %v", err)
	}
}

// TestCleanupErrorsWhenProviderMissing guards against the orphan-leak regression:
// when the AuthentikProvider can't be read, cleanup must return an error so the
// finalizer is retained and the Authentik resources are not silently leaked.
// TestReconcileEnvoyModeNoHostnames verifies a fronted app whose route declares
// no hostnames (and has no explicit redirectURIs) is flagged rather than silently
// provisioned with zero callback URIs.
func TestReconcileEnvoyModeNoHostnames(t *testing.T) {
	scheme := newTestScheme()
	state := &fakeServerState{}
	server := fakeAuthentikServer(state, false)
	defer server.Close()

	route := &gwapiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "my-route", Namespace: "test-ns"},
		Spec:       gwapiv1.HTTPRouteSpec{}, // no hostnames
	}
	app := &v1alpha1.OIDCApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns", Finalizers: []string{finalizerName}},
		Spec: v1alpha1.OIDCApplicationSpec{
			ProviderRef: v1alpha1.ProviderRef{Name: "main"},
			SigningKey:  "Self-signed Certificate",
			Groups:      []v1alpha1.GroupRef{{Name: "admins"}},
			TargetRefs:  []v1alpha1.TargetRef{{Name: "my-route"}},
		},
	}
	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(connectedProvider(server.URL), tokenSecret(), route, app).
		WithStatusSubresource(app).
		Build()

	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-app", Namespace: "test-ns"},
	})
	if err != nil {
		t.Fatalf("Reconcile should requeue, not error: %v", err)
	}
	if result.RequeueAfter == 0 {
		t.Error("expected requeue when no redirect URIs can be derived")
	}
	if state.providerPost {
		t.Error("must not create an Authentik provider with zero redirect URIs")
	}

	var updated v1alpha1.OIDCApplication
	if err := k8s.Get(context.Background(), types.NamespacedName{Name: "test-app", Namespace: "test-ns"}, &updated); err != nil {
		t.Fatalf("get app: %v", err)
	}
	if len(updated.Status.Conditions) == 0 || updated.Status.Conditions[0].Reason != "NoRedirectURIs" {
		t.Errorf("expected NoRedirectURIs condition, got %+v", updated.Status.Conditions)
	}
}

func TestCleanupErrorsWhenProviderMissing(t *testing.T) {
	scheme := newTestScheme()
	app := &v1alpha1.OIDCApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns"},
		Spec:       v1alpha1.OIDCApplicationSpec{ProviderRef: v1alpha1.ProviderRef{Name: "main"}},
		Status: v1alpha1.OIDCApplicationStatus{
			Authentik: &v1alpha1.AuthentikStatus{ProviderID: 1, ApplicationSlug: "test-ns-test-app"},
		},
	}
	k8s := fake.NewClientBuilder().WithScheme(scheme).WithObjects(app).Build()
	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
	if err := reconciler.cleanup(context.Background(), app); err == nil {
		t.Fatal("expected cleanup to error (retain finalizer) when the provider is unreachable")
	}
}

// TestCleanupDeletesAuthentikResources verifies the happy path issues DELETEs for
// the tracked bindings, application, and provider.
func TestCleanupDeletesAuthentikResources(t *testing.T) {
	scheme := newTestScheme()
	var deletedBinding, deletedApp, deletedProvider bool
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/policies/bindings/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deletedBinding = true
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/api/v3/core/applications/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deletedApp = true
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/api/v3/providers/oauth2/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deletedProvider = true
		}
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	app := &v1alpha1.OIDCApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "test-app", Namespace: "test-ns"},
		Spec:       v1alpha1.OIDCApplicationSpec{ProviderRef: v1alpha1.ProviderRef{Name: "main"}},
		Status: v1alpha1.OIDCApplicationStatus{
			Authentik: &v1alpha1.AuthentikStatus{
				ProviderID:       1,
				ApplicationSlug:  "test-ns-test-app",
				PolicyBindingIDs: []string{"binding-uuid-1"},
			},
		},
	}
	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(connectedProvider(server.URL), tokenSecret(), app).
		Build()
	reconciler := &OIDCApplicationReconciler{Client: k8s, Scheme: scheme}
	if err := reconciler.cleanup(context.Background(), app); err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}
	if !deletedBinding || !deletedApp || !deletedProvider {
		t.Errorf("expected DELETE of binding/app/provider, got binding=%v app=%v provider=%v",
			deletedBinding, deletedApp, deletedProvider)
	}
}
