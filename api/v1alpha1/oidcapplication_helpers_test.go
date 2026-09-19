package v1alpha1_test

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/authentik-envoy-operator/authentik-envoy-operator/api/v1alpha1"
)

func app(name, ns string, spec v1alpha1.OIDCApplicationSpec) *v1alpha1.OIDCApplication {
	return &v1alpha1.OIDCApplication{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       spec,
	}
}

func TestEffectiveSlugDefault(t *testing.T) {
	a := app("grafana", "monitoring", v1alpha1.OIDCApplicationSpec{})
	if got := a.EffectiveSlug(); got != "monitoring-grafana" {
		t.Errorf("expected monitoring-grafana, got %s", got)
	}
}

func TestEffectiveSlugOverride(t *testing.T) {
	a := app("grafana", "monitoring", v1alpha1.OIDCApplicationSpec{Slug: "graf"})
	if got := a.EffectiveSlug(); got != "graf" {
		t.Errorf("expected graf, got %s", got)
	}
}

func TestEffectiveDisplayName(t *testing.T) {
	a := app("grafana", "monitoring", v1alpha1.OIDCApplicationSpec{})
	if a.EffectiveDisplayName() != "grafana" {
		t.Errorf("display name default should be metadata.name")
	}
	a.Spec.DisplayName = "Grafana"
	if a.EffectiveDisplayName() != "Grafana" {
		t.Errorf("display name override not honored")
	}
}

func TestEffectiveSecretNames(t *testing.T) {
	a := app("grafana", "monitoring", v1alpha1.OIDCApplicationSpec{})
	if got := a.EffectiveSecretName(); got != "grafana-oidc" {
		t.Fatalf("application secret name = %q, want grafana-oidc", got)
	}
	if got := a.EnvoySecretName(); got != "grafana-envoy-oidc" {
		t.Fatalf("Envoy secret name = %q, want grafana-envoy-oidc", got)
	}

	a.Spec.SecretName = "grafana-config"
	if got := a.EffectiveSecretName(); got != "grafana-config" {
		t.Fatalf("overridden application secret name = %q, want grafana-config", got)
	}
	if got := a.EnvoySecretName(); got != "grafana-envoy-oidc" {
		t.Fatalf("Envoy secret name changed with application override: %q", got)
	}
}

func TestEffectiveScopesDefault(t *testing.T) {
	a := app("g", "m", v1alpha1.OIDCApplicationSpec{})
	got := a.EffectiveScopes()
	if len(got) != 2 || got[0] != "openid" || got[1] != "profile" {
		t.Errorf("expected default [openid profile], got %v", got)
	}
}

func TestCookiePrefix(t *testing.T) {
	a := app("grafana", "m", v1alpha1.OIDCApplicationSpec{})
	if a.CookiePrefix() != "grafana" {
		t.Errorf("default cookie prefix should be name")
	}
	a.Spec.CookieConfig = &v1alpha1.CookieConfig{NamePrefix: "gf"}
	if a.CookiePrefix() != "gf" {
		t.Errorf("cookie prefix override not honored")
	}
}

func TestForwardAccessTokenEnabled(t *testing.T) {
	// Unset defaults to true.
	a := app("g", "m", v1alpha1.OIDCApplicationSpec{})
	if !a.ForwardAccessTokenEnabled() {
		t.Error("expected forwardAccessToken to default to true when unset")
	}
	// Explicit false is honored (regression: a value bool + omitempty reverted it).
	f := false
	a.Spec.ForwardAccessToken = &f
	if a.ForwardAccessTokenEnabled() {
		t.Error("expected explicit false to be honored")
	}
	tr := true
	a.Spec.ForwardAccessToken = &tr
	if !a.ForwardAccessTokenEnabled() {
		t.Error("expected explicit true to be honored")
	}
}
