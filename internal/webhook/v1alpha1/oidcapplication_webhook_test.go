package v1alpha1_test

import (
	"context"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv1alpha1 "github.com/authentik-envoy-operator/authentik-envoy-operator/api/v1alpha1"
	webhookv1alpha1 "github.com/authentik-envoy-operator/authentik-envoy-operator/internal/webhook/v1alpha1"
)

func base() *apiv1alpha1.OIDCApplication {
	return &apiv1alpha1.OIDCApplication{
		ObjectMeta: metav1.ObjectMeta{Name: "g", Namespace: "m"},
		Spec: apiv1alpha1.OIDCApplicationSpec{
			ProviderRef: apiv1alpha1.ProviderRef{Name: "main"},
			SigningKey:  "key",
			Scopes:      []string{"openid"},
			Groups:      []apiv1alpha1.GroupRef{{Name: "admins"}},
		},
	}
}

func TestValidateCreateOK(t *testing.T) {
	v := &webhookv1alpha1.OIDCApplicationCustomValidator{}
	if _, err := v.ValidateCreate(context.Background(), base()); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestValidateCreateNoGroups(t *testing.T) {
	v := &webhookv1alpha1.OIDCApplicationCustomValidator{}
	obj := base()
	obj.Spec.Groups = nil
	if _, err := v.ValidateCreate(context.Background(), obj); err == nil {
		t.Fatal("expected error when no groups")
	}
}

func TestValidateScopesMissingOpenid(t *testing.T) {
	v := &webhookv1alpha1.OIDCApplicationCustomValidator{}
	obj := base()
	obj.Spec.Scopes = []string{"profile"}
	if _, err := v.ValidateCreate(context.Background(), obj); err == nil {
		t.Fatal("expected error when scopes lack openid")
	}
}

func TestValidateSlugImmutable(t *testing.T) {
	v := &webhookv1alpha1.OIDCApplicationCustomValidator{}
	oldObj := base()
	oldObj.Spec.Slug = "a"
	newObj := base()
	newObj.Spec.Slug = "b"
	_, err := v.ValidateUpdate(context.Background(), oldObj, newObj)
	if err == nil {
		t.Fatal("expected error when slug changes")
	}
	assertInvalidCause(t, err, "spec.slug")
}

// TestValidateSlugImmutableAllowsSettingEffectiveValue ensures pinning the slug to
// its current effective value ("<ns>-<name>") is not treated as a change.
func TestValidateSlugImmutableAllowsSettingEffectiveValue(t *testing.T) {
	v := &webhookv1alpha1.OIDCApplicationCustomValidator{}
	oldObj := base() // Slug unset ⇒ effective "m-g"
	newObj := base()
	newObj.Spec.Slug = "m-g"
	if _, err := v.ValidateUpdate(context.Background(), oldObj, newObj); err != nil {
		t.Fatalf("expected pinning slug to its effective value to be allowed, got %v", err)
	}
}

func TestValidateRejectsLongEffectiveSlug(t *testing.T) {
	v := &webhookv1alpha1.OIDCApplicationCustomValidator{}
	obj := base()
	obj.Spec.Slug = "s-" + strings.Repeat("x", 60) // > 50 chars
	if _, err := v.ValidateCreate(context.Background(), obj); err == nil {
		t.Fatal("expected error when effective slug exceeds 50 characters")
	}
}

func TestValidateRejectsUnsupportedTargetRefKind(t *testing.T) {
	v := &webhookv1alpha1.OIDCApplicationCustomValidator{}
	obj := base()
	obj.Spec.TargetRefs = []apiv1alpha1.TargetRef{{Kind: "GRPCRoute", Name: "r"}}
	if _, err := v.ValidateCreate(context.Background(), obj); err == nil {
		t.Fatal("expected error for unsupported targetRef kind")
	}
	// The supported HTTPRoute kind (and the empty default) must pass.
	obj.Spec.TargetRefs = []apiv1alpha1.TargetRef{{Kind: "HTTPRoute", Group: "gateway.networking.k8s.io", Name: "r"}}
	if _, err := v.ValidateCreate(context.Background(), obj); err != nil {
		t.Fatalf("expected HTTPRoute targetRef to be valid, got %v", err)
	}
}

func TestValidateSecretTemplateKeys(t *testing.T) {
	v := &webhookv1alpha1.OIDCApplicationCustomValidator{}

	for _, key := range []string{"OIDC_CLIENT_ID", "config.json", ".dockerconfigjson", "a-b", strings.Repeat("a", 253)} {
		t.Run("accepts "+key, func(t *testing.T) {
			obj := base()
			obj.Spec.SecretTemplate = map[string]string{key: "value"}
			if _, err := v.ValidateCreate(context.Background(), obj); err != nil {
				t.Fatalf("expected Secret template key %q to be valid, got %v", key, err)
			}
		})
	}

	for name, key := range map[string]string{
		"slash":    "client/id",
		"space":    "client id",
		"empty":    "",
		"too long": strings.Repeat("a", 254),
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			obj := base()
			obj.Spec.SecretTemplate = map[string]string{key: "value"}
			_, err := v.ValidateCreate(context.Background(), obj)
			if err == nil {
				t.Fatalf("expected Secret template key %q to be rejected", key)
			}
			wantPath := "spec.secretTemplate[" + key + "]"
			assertInvalidCause(t, err, wantPath)
		})
	}
}

func TestValidateRejectsSecretNameCollision(t *testing.T) {
	v := &webhookv1alpha1.OIDCApplicationCustomValidator{}
	obj := base()
	obj.Spec.SecretTemplate = map[string]string{"client-id": "value"}
	obj.Spec.SecretName = obj.EnvoySecretName()
	obj.Spec.TargetRefs = []apiv1alpha1.TargetRef{{Name: "route"}}

	_, err := v.ValidateCreate(context.Background(), obj)
	if err == nil {
		t.Fatal("expected colliding application and Envoy Secret names to be rejected")
	}
	assertInvalidCause(t, err, "spec.secretName")
	if !strings.Contains(err.Error(), "must differ from the Envoy Secret name") {
		t.Fatalf("collision error is unclear: %v", err)
	}
}

func TestValidateApplicationSecretName(t *testing.T) {
	v := &webhookv1alpha1.OIDCApplicationCustomValidator{}

	t.Run("ignores invalid explicit name without template", func(t *testing.T) {
		obj := base()
		obj.Spec.SecretName = "Not Valid"
		if _, err := v.ValidateCreate(context.Background(), obj); err != nil {
			t.Fatalf("expected unused Secret name to be ignored, got %v", err)
		}
	})

	t.Run("rejects invalid explicit name at spec field", func(t *testing.T) {
		obj := base()
		obj.Spec.SecretTemplate = map[string]string{"client-id": "value"}
		obj.Spec.SecretName = "Not Valid"
		_, err := v.ValidateCreate(context.Background(), obj)
		if err == nil {
			t.Fatal("expected invalid explicit Secret name to be rejected")
		}
		if !strings.Contains(err.Error(), "spec.secretName") {
			t.Fatalf("error %q does not contain spec.secretName", err)
		}
		if strings.Contains(err.Error(), "metadata.name") {
			t.Fatalf("explicit Secret name produced duplicate metadata.name error: %v", err)
		}
	})

	t.Run("accepts 253 character derived name", func(t *testing.T) {
		obj := base()
		obj.Name = dnsName(248)
		obj.Spec.Slug = "short"
		obj.Spec.SecretTemplate = map[string]string{"client-id": "value"}
		if _, err := v.ValidateCreate(context.Background(), obj); err != nil {
			t.Fatalf("expected 253 character derived Secret name to be valid, got %v", err)
		}
	})

	t.Run("rejects 254 character derived name at metadata name", func(t *testing.T) {
		obj := base()
		obj.Name = dnsName(249)
		obj.Spec.Slug = "short"
		obj.Spec.SecretTemplate = map[string]string{"client-id": "value"}
		_, err := v.ValidateCreate(context.Background(), obj)
		if err == nil {
			t.Fatal("expected 254 character derived Secret name to be rejected")
		}
		if !strings.Contains(err.Error(), "metadata.name") || !strings.Contains(err.Error(), "-oidc suffix") {
			t.Fatalf("error %q does not identify metadata.name and the -oidc suffix", err)
		}
	})
}

func TestValidateEnvoySecretName(t *testing.T) {
	v := &webhookv1alpha1.OIDCApplicationCustomValidator{}

	t.Run("ignores derived name without target refs", func(t *testing.T) {
		obj := base()
		obj.Name = dnsName(243)
		obj.Spec.Slug = "short"
		if _, err := v.ValidateCreate(context.Background(), obj); err != nil {
			t.Fatalf("expected unused Envoy Secret name to be ignored, got %v", err)
		}
	})

	t.Run("accepts 253 character derived name", func(t *testing.T) {
		obj := base()
		obj.Name = dnsName(242)
		obj.Spec.Slug = "short"
		obj.Spec.TargetRefs = []apiv1alpha1.TargetRef{{Name: "route"}}
		if _, err := v.ValidateCreate(context.Background(), obj); err != nil {
			t.Fatalf("expected 253 character Envoy Secret name to be valid, got %v", err)
		}
	})

	t.Run("rejects 254 character derived name", func(t *testing.T) {
		obj := base()
		obj.Name = dnsName(243)
		obj.Spec.Slug = "short"
		obj.Spec.TargetRefs = []apiv1alpha1.TargetRef{{Name: "route"}}
		_, err := v.ValidateCreate(context.Background(), obj)
		if err == nil {
			t.Fatal("expected 254 character Envoy Secret name to be rejected")
		}
		if !strings.Contains(err.Error(), "metadata.name") || !strings.Contains(err.Error(), "-envoy-oidc suffix") {
			t.Fatalf("error %q does not identify metadata.name and the -envoy-oidc suffix", err)
		}
	})
}

func dnsName(length int) string {
	const label = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	var parts []string
	for length > len(label) {
		parts = append(parts, label)
		length -= len(label) + 1
	}
	parts = append(parts, strings.Repeat("a", length))
	return strings.Join(parts, ".")
}

func assertInvalidCause(t *testing.T, err error, path string) {
	t.Helper()
	if !apierrors.IsInvalid(err) {
		t.Fatalf("expected Kubernetes Invalid error, got %T: %v", err, err)
	}
	status := err.(apierrors.APIStatus).Status()
	if status.Reason != metav1.StatusReasonInvalid {
		t.Fatalf("status reason = %q, want %q", status.Reason, metav1.StatusReasonInvalid)
	}
	if status.Details == nil {
		t.Fatal("Invalid error has no status details")
	}
	for _, cause := range status.Details.Causes {
		if cause.Field == path {
			return
		}
	}
	t.Fatalf("Invalid error causes %#v do not contain field %q", status.Details.Causes, path)
}
