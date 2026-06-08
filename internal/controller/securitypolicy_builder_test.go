package controller

import (
	"testing"

	v1alpha1 "github.com/authentik-envoy-operator/authentik-envoy-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestBuildSecurityPolicy(t *testing.T) {
	policy := &v1alpha1.OIDCPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grafana-oidc",
			Namespace: "monitoring",
			UID:       "test-uid",
		},
		Spec: v1alpha1.OIDCPolicySpec{
			TargetRefs: []v1alpha1.TargetRef{
				{Name: "grafana"},
			},
			OIDC: v1alpha1.OIDCConfig{
				AllowedGroups:      []string{"admins", "developers"},
				Scopes:             []string{"openid", "profile"},
				ForwardAccessToken: true,
			},
		},
	}

	params := SecurityPolicyParams{
		AuthentikHost:   "https://authentik.example.com",
		ApplicationSlug: "monitoring-grafana-oidc",
		ClientID:        "monitoring-grafana-oidc",
		SecretName:      "grafana-oidc-client-secret",
	}

	sp := BuildSecurityPolicy(policy, policy.Spec.TargetRefs[0], params)

	if sp.Name != "grafana-oidc-grafana" {
		t.Errorf("expected name grafana-oidc-grafana, got %s", sp.Name)
	}
	if sp.Namespace != "monitoring" {
		t.Errorf("expected namespace monitoring, got %s", sp.Namespace)
	}
	if len(sp.OwnerReferences) != 1 {
		t.Fatalf("expected 1 owner reference, got %d", len(sp.OwnerReferences))
	}
	if sp.OwnerReferences[0].Name != "grafana-oidc" {
		t.Errorf("expected owner grafana-oidc, got %s", sp.OwnerReferences[0].Name)
	}

	// Verify OIDC config
	if sp.Spec.OIDC == nil {
		t.Fatal("expected OIDC spec to be set")
	}
	if *sp.Spec.OIDC.ClientID != "monitoring-grafana-oidc" {
		t.Errorf("expected clientID monitoring-grafana-oidc, got %s", *sp.Spec.OIDC.ClientID)
	}
	if sp.Spec.OIDC.Provider.Issuer != "https://authentik.example.com/application/o/monitoring-grafana-oidc/" {
		t.Errorf("unexpected issuer: %s", sp.Spec.OIDC.Provider.Issuer)
	}
	if sp.Spec.OIDC.ForwardAccessToken == nil || !*sp.Spec.OIDC.ForwardAccessToken {
		t.Error("expected forwardAccessToken to be true")
	}

	// Verify JWT config
	if sp.Spec.JWT == nil {
		t.Fatal("expected JWT spec to be set")
	}
	if len(sp.Spec.JWT.Providers) != 1 {
		t.Fatalf("expected 1 JWT provider, got %d", len(sp.Spec.JWT.Providers))
	}
	if sp.Spec.JWT.Providers[0].Name != "authentik" {
		t.Errorf("expected JWT provider name authentik, got %s", sp.Spec.JWT.Providers[0].Name)
	}

	// Verify Authorization config
	if sp.Spec.Authorization == nil {
		t.Fatal("expected Authorization spec to be set")
	}
	if len(sp.Spec.Authorization.Rules) != 1 {
		t.Fatalf("expected 1 authorization rule, got %d", len(sp.Spec.Authorization.Rules))
	}
	rule := sp.Spec.Authorization.Rules[0]
	if rule.Principal.JWT == nil {
		t.Fatal("expected JWT principal")
	}
	if len(rule.Principal.JWT.Claims) != 1 {
		t.Fatalf("expected 1 claim, got %d", len(rule.Principal.JWT.Claims))
	}
	if rule.Principal.JWT.Claims[0].Name != "groups" {
		t.Errorf("expected claim name 'groups', got %s", rule.Principal.JWT.Claims[0].Name)
	}
	if len(rule.Principal.JWT.Claims[0].Values) != 2 {
		t.Errorf("expected 2 allowed groups, got %d", len(rule.Principal.JWT.Claims[0].Values))
	}

	// Verify targetRefs
	if len(sp.Spec.TargetRefs) != 1 {
		t.Fatalf("expected 1 targetRef, got %d", len(sp.Spec.TargetRefs))
	}
	if string(sp.Spec.TargetRefs[0].Name) != "grafana" {
		t.Errorf("expected targetRef name grafana, got %s", sp.Spec.TargetRefs[0].Name)
	}
}

func TestBuildSecurityPolicyCookieNames(t *testing.T) {
	policy := &v1alpha1.OIDCPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "myapp-oidc",
			Namespace: "default",
			UID:       "uid",
		},
		Spec: v1alpha1.OIDCPolicySpec{
			TargetRefs: []v1alpha1.TargetRef{{Name: "myapp"}},
			OIDC: v1alpha1.OIDCConfig{
				AllowedGroups: []string{"users"},
				Scopes:        []string{"openid"},
			},
		},
	}

	params := SecurityPolicyParams{
		AuthentikHost:   "https://auth.example.com",
		ApplicationSlug: "default-myapp-oidc",
		ClientID:        "default-myapp-oidc",
		SecretName:      "myapp-oidc-client-secret",
	}

	sp := BuildSecurityPolicy(policy, policy.Spec.TargetRefs[0], params)

	if sp.Spec.OIDC.CookieNames == nil {
		t.Fatal("expected cookie names to be set")
	}
	if *sp.Spec.OIDC.CookieNames.AccessToken != "myapp-oidc-accessToken" {
		t.Errorf("unexpected access token cookie: %s", *sp.Spec.OIDC.CookieNames.AccessToken)
	}
	if *sp.Spec.OIDC.CookieNames.IDToken != "myapp-oidc-idToken" {
		t.Errorf("unexpected id token cookie: %s", *sp.Spec.OIDC.CookieNames.IDToken)
	}
}

func TestBuildSecurityPolicyCustomCookiePrefix(t *testing.T) {
	policy := &v1alpha1.OIDCPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app-oidc",
			Namespace: "default",
			UID:       "uid",
		},
		Spec: v1alpha1.OIDCPolicySpec{
			TargetRefs: []v1alpha1.TargetRef{{Name: "app"}},
			OIDC: v1alpha1.OIDCConfig{
				AllowedGroups: []string{"users"},
				Scopes:        []string{"openid"},
				CookieConfig: &v1alpha1.CookieConfig{
					NamePrefix: "custom",
				},
			},
		},
	}

	params := SecurityPolicyParams{
		AuthentikHost:   "https://auth.example.com",
		ApplicationSlug: "default-app-oidc",
		ClientID:        "default-app-oidc",
		SecretName:      "app-oidc-client-secret",
	}

	sp := BuildSecurityPolicy(policy, policy.Spec.TargetRefs[0], params)

	if *sp.Spec.OIDC.CookieNames.AccessToken != "custom-accessToken" {
		t.Errorf("unexpected access token cookie: %s", *sp.Spec.OIDC.CookieNames.AccessToken)
	}
}

func TestBuildSecurityPolicyCreatesValidObject(t *testing.T) {
	policy := &v1alpha1.OIDCPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "test-ns",
			UID:       "test-uid-123",
		},
		Spec: v1alpha1.OIDCPolicySpec{
			TargetRefs: []v1alpha1.TargetRef{{Name: "my-route"}},
			OIDC: v1alpha1.OIDCConfig{
				AllowedGroups: []string{"admins"},
			},
		},
	}

	params := SecurityPolicyParams{
		AuthentikHost:   "https://auth.example.com",
		ApplicationSlug: "test-ns-test-policy",
		ClientID:        "test-ns-test-policy",
		SecretName:      "test-policy-client-secret",
	}

	sp := BuildSecurityPolicy(policy, policy.Spec.TargetRefs[0], params)

	// Should produce a fully typed SecurityPolicy ready for CreateOrUpdate
	if sp.APIVersion != "gateway.envoyproxy.io/v1alpha1" {
		t.Errorf("expected apiVersion gateway.envoyproxy.io/v1alpha1, got %s", sp.APIVersion)
	}
	if sp.Kind != "SecurityPolicy" {
		t.Errorf("expected kind SecurityPolicy, got %s", sp.Kind)
	}
	if string(sp.Spec.OIDC.ClientSecret.Name) != "test-policy-client-secret" {
		t.Errorf("unexpected client secret name: %s", sp.Spec.OIDC.ClientSecret.Name)
	}
}
