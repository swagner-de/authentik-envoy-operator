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

	if sp.Spec.OIDC.CookieNames.AccessToken != "myapp-oidc-accessToken" {
		t.Errorf("unexpected access token cookie: %s", sp.Spec.OIDC.CookieNames.AccessToken)
	}
	if sp.Spec.OIDC.CookieNames.IDToken != "myapp-oidc-idToken" {
		t.Errorf("unexpected id token cookie: %s", sp.Spec.OIDC.CookieNames.IDToken)
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

	if sp.Spec.OIDC.CookieNames.AccessToken != "custom-accessToken" {
		t.Errorf("unexpected access token cookie: %s", sp.Spec.OIDC.CookieNames.AccessToken)
	}
}
