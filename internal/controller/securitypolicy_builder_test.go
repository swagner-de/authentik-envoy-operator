package controller_test

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/authentik-envoy-operator/authentik-envoy-operator/api/v1alpha1"
	"github.com/authentik-envoy-operator/authentik-envoy-operator/internal/controller"
)

func TestBuildSecurityPolicyAuthorizesOnGroupsOnly(t *testing.T) {
	forward := true
	app := &v1alpha1.OIDCApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "grafana", Namespace: "monitoring", UID: "app-uid"},
		Spec: v1alpha1.OIDCApplicationSpec{
			Groups:             []v1alpha1.GroupRef{{Name: "admins"}, {Name: "devs"}},
			ForwardAccessToken: &forward,
		},
	}

	sp := controller.BuildSecurityPolicy(app, v1alpha1.TargetRef{Name: "route"}, controller.SecurityPolicyParams{
		AuthentikHost:   "https://auth.example.com/",
		ApplicationSlug: "monitoring-grafana",
		ClientID:        "monitoring-grafana",
		SecretName:      "grafana-oidc",
	})

	if sp.Spec.Authorization == nil || len(sp.Spec.Authorization.Rules) != 1 {
		t.Fatalf("expected 1 authorization rule")
	}
	rule := sp.Spec.Authorization.Rules[0]
	if rule.Principal.JWT == nil {
		t.Fatal("expected JWT principal")
	}

	// (a) No hardcoded scopes on the JWT principal.
	if len(rule.Principal.JWT.Scopes) != 0 {
		t.Errorf("expected no hardcoded scopes on the JWT principal, got %+v", rule.Principal.JWT.Scopes)
	}

	// (b) The groups claim Values equal the group names.
	if len(rule.Principal.JWT.Claims) != 1 {
		t.Fatalf("expected 1 claim, got %d", len(rule.Principal.JWT.Claims))
	}
	claim := rule.Principal.JWT.Claims[0]
	if claim.Name != "groups" || len(claim.Values) != 2 {
		t.Errorf("expected groups claim with 2 values, got %+v", claim)
	}
	if claim.Values[0] != "admins" || claim.Values[1] != "devs" {
		t.Errorf("expected group names [admins devs], got %v", claim.Values)
	}

	// (c) Issuer has no double slash when the host ends in '/'.
	if got := sp.Spec.JWT.Providers[0].Issuer; got != "https://auth.example.com/application/o/monitoring-grafana/" {
		t.Errorf("issuer double-slash not normalized: %s", got)
	}
	if got := sp.Spec.JWT.Providers[0].RemoteJWKS.URI; got != "https://auth.example.com/application/o/monitoring-grafana/jwks/" {
		t.Errorf("jwksURI double-slash not normalized: %s", got)
	}
	if got := sp.Spec.OIDC.Provider.Issuer; got != "https://auth.example.com/application/o/monitoring-grafana/" {
		t.Errorf("OIDC issuer double-slash not normalized: %s", got)
	}
}

func TestBuildSecurityPolicyMetadata(t *testing.T) {
	app := &v1alpha1.OIDCApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "grafana", Namespace: "monitoring", UID: "app-uid"},
		Spec: v1alpha1.OIDCApplicationSpec{
			Groups: []v1alpha1.GroupRef{{Name: "admins"}},
		},
	}

	sp := controller.BuildSecurityPolicy(app, v1alpha1.TargetRef{Name: "route"}, controller.SecurityPolicyParams{
		AuthentikHost:   "https://auth.example.com",
		ApplicationSlug: "monitoring-grafana",
		ClientID:        "monitoring-grafana",
		SecretName:      "grafana-oidc",
	})

	if sp.Name != "grafana-route" {
		t.Errorf("expected name grafana-route, got %s", sp.Name)
	}
	if sp.Namespace != "monitoring" {
		t.Errorf("expected namespace monitoring, got %s", sp.Namespace)
	}
	if len(sp.OwnerReferences) != 1 {
		t.Fatalf("expected 1 owner reference, got %d", len(sp.OwnerReferences))
	}
	owner := sp.OwnerReferences[0]
	if owner.Kind != "OIDCApplication" {
		t.Errorf("expected owner kind OIDCApplication, got %s", owner.Kind)
	}
	if owner.Name != "grafana" || owner.UID != "app-uid" {
		t.Errorf("unexpected owner ref: %+v", owner)
	}
}

func TestBuildSecurityPolicyCookiePrefix(t *testing.T) {
	app := &v1alpha1.OIDCApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "grafana", Namespace: "monitoring"},
		Spec: v1alpha1.OIDCApplicationSpec{
			Groups:       []v1alpha1.GroupRef{{Name: "admins"}},
			CookieConfig: &v1alpha1.CookieConfig{NamePrefix: "gf"},
		},
	}

	sp := controller.BuildSecurityPolicy(app, v1alpha1.TargetRef{Name: "route"}, controller.SecurityPolicyParams{
		AuthentikHost:   "https://auth.example.com",
		ApplicationSlug: "monitoring-grafana",
		ClientID:        "monitoring-grafana",
		SecretName:      "grafana-oidc",
	})

	if *sp.Spec.OIDC.CookieNames.AccessToken != "gf-accessToken" {
		t.Errorf("unexpected access token cookie: %s", *sp.Spec.OIDC.CookieNames.AccessToken)
	}
	if *sp.Spec.OIDC.CookieNames.IDToken != "gf-idToken" {
		t.Errorf("unexpected id token cookie: %s", *sp.Spec.OIDC.CookieNames.IDToken)
	}
}

func TestBuildSecurityPolicyCookieConfigWired(t *testing.T) {
	forward := false
	app := &v1alpha1.OIDCApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "grafana", Namespace: "monitoring"},
		Spec: v1alpha1.OIDCApplicationSpec{
			Groups:             []v1alpha1.GroupRef{{Name: "admins"}},
			ForwardAccessToken: &forward,
			CookieConfig:       &v1alpha1.CookieConfig{SameSite: "Strict", Domain: "example.com"},
		},
	}

	sp := controller.BuildSecurityPolicy(app, v1alpha1.TargetRef{Name: "route"}, controller.SecurityPolicyParams{
		AuthentikHost:   "https://auth.example.com",
		ApplicationSlug: "monitoring-grafana",
		ClientID:        "monitoring-grafana",
		SecretName:      "grafana-oidc",
	})

	if sp.Spec.OIDC.CookieConfig == nil || sp.Spec.OIDC.CookieConfig.SameSite == nil || *sp.Spec.OIDC.CookieConfig.SameSite != "Strict" {
		t.Errorf("expected SameSite=Strict wired into OIDC cookie config, got %+v", sp.Spec.OIDC.CookieConfig)
	}
	if sp.Spec.OIDC.CookieDomain == nil || *sp.Spec.OIDC.CookieDomain != "example.com" {
		t.Errorf("expected cookieDomain=example.com, got %v", sp.Spec.OIDC.CookieDomain)
	}
	if sp.Spec.OIDC.ForwardAccessToken == nil || *sp.Spec.OIDC.ForwardAccessToken {
		t.Errorf("expected forwardAccessToken=false to be honored, got %v", sp.Spec.OIDC.ForwardAccessToken)
	}
}
