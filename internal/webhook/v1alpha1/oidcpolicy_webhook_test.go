/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/authentik-envoy-operator/authentik-envoy-operator/api/v1alpha1"
)

func TestOIDCPolicyValidation_MissingGroups(t *testing.T) {
	v := &OIDCPolicyCustomValidator{}
	policy := &v1alpha1.OIDCPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
		Spec: v1alpha1.OIDCPolicySpec{
			ProviderRef: v1alpha1.ProviderRef{Name: "main"},
			TargetRefs:  []v1alpha1.TargetRef{{Name: "route"}},
			OIDC: v1alpha1.OIDCConfig{
				AllowedGroups: []string{},
				Scopes:        []string{"openid"},
			},
		},
	}
	_, err := v.ValidateCreate(context.Background(), policy)
	if err == nil {
		t.Fatal("expected validation error for empty allowedGroups")
	}
}

func TestOIDCPolicyValidation_MissingOpenIDScope(t *testing.T) {
	v := &OIDCPolicyCustomValidator{}
	policy := &v1alpha1.OIDCPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
		Spec: v1alpha1.OIDCPolicySpec{
			ProviderRef: v1alpha1.ProviderRef{Name: "main"},
			TargetRefs:  []v1alpha1.TargetRef{{Name: "route"}},
			OIDC: v1alpha1.OIDCConfig{
				AllowedGroups: []string{"admins"},
				Scopes:        []string{"profile"},
			},
		},
	}
	_, err := v.ValidateCreate(context.Background(), policy)
	if err == nil {
		t.Fatal("expected validation error for missing openid scope")
	}
}

func TestOIDCPolicyValidation_Valid(t *testing.T) {
	v := &OIDCPolicyCustomValidator{}
	policy := &v1alpha1.OIDCPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
		Spec: v1alpha1.OIDCPolicySpec{
			ProviderRef: v1alpha1.ProviderRef{Name: "main"},
			TargetRefs:  []v1alpha1.TargetRef{{Name: "route"}},
			OIDC: v1alpha1.OIDCConfig{
				AllowedGroups: []string{"admins"},
				Scopes:        []string{"openid", "profile"},
			},
		},
	}
	_, err := v.ValidateCreate(context.Background(), policy)
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestOIDCPolicyValidation_InvalidSameSite(t *testing.T) {
	v := &OIDCPolicyCustomValidator{}
	policy := &v1alpha1.OIDCPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
		Spec: v1alpha1.OIDCPolicySpec{
			ProviderRef: v1alpha1.ProviderRef{Name: "main"},
			TargetRefs:  []v1alpha1.TargetRef{{Name: "route"}},
			OIDC: v1alpha1.OIDCConfig{
				AllowedGroups: []string{"admins"},
				Scopes:        []string{"openid"},
				CookieConfig: &v1alpha1.CookieConfig{
					SameSite: "Invalid",
				},
			},
		},
	}
	_, err := v.ValidateCreate(context.Background(), policy)
	if err == nil {
		t.Fatal("expected validation error for invalid SameSite")
	}
}

func TestOIDCPolicyValidation_MissingTargetRefs(t *testing.T) {
	v := &OIDCPolicyCustomValidator{}
	policy := &v1alpha1.OIDCPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
		Spec: v1alpha1.OIDCPolicySpec{
			ProviderRef: v1alpha1.ProviderRef{Name: "main"},
			TargetRefs:  []v1alpha1.TargetRef{},
			OIDC: v1alpha1.OIDCConfig{
				AllowedGroups: []string{"admins"},
				Scopes:        []string{"openid"},
			},
		},
	}
	_, err := v.ValidateCreate(context.Background(), policy)
	if err == nil {
		t.Fatal("expected validation error for empty targetRefs")
	}
}

func TestOIDCPolicyValidation_ValidUpdate(t *testing.T) {
	v := &OIDCPolicyCustomValidator{}
	oldPolicy := &v1alpha1.OIDCPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
		Spec: v1alpha1.OIDCPolicySpec{
			ProviderRef: v1alpha1.ProviderRef{Name: "main"},
			TargetRefs:  []v1alpha1.TargetRef{{Name: "route"}},
			OIDC: v1alpha1.OIDCConfig{
				AllowedGroups: []string{"admins"},
				Scopes:        []string{"openid"},
			},
		},
	}
	newPolicy := &v1alpha1.OIDCPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
		Spec: v1alpha1.OIDCPolicySpec{
			ProviderRef: v1alpha1.ProviderRef{Name: "main"},
			TargetRefs:  []v1alpha1.TargetRef{{Name: "route"}},
			OIDC: v1alpha1.OIDCConfig{
				AllowedGroups: []string{"admins", "editors"},
				Scopes:        []string{"openid", "email"},
			},
		},
	}
	_, err := v.ValidateUpdate(context.Background(), oldPolicy, newPolicy)
	if err != nil {
		t.Fatalf("unexpected validation error on update: %v", err)
	}
}

func TestOIDCPolicyValidation_ValidSameSite(t *testing.T) {
	v := &OIDCPolicyCustomValidator{}
	for _, sameSite := range []string{"Lax", "Strict", "None"} {
		policy := &v1alpha1.OIDCPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
			Spec: v1alpha1.OIDCPolicySpec{
				ProviderRef: v1alpha1.ProviderRef{Name: "main"},
				TargetRefs:  []v1alpha1.TargetRef{{Name: "route"}},
				OIDC: v1alpha1.OIDCConfig{
					AllowedGroups: []string{"admins"},
					Scopes:        []string{"openid"},
					CookieConfig: &v1alpha1.CookieConfig{
						SameSite: sameSite,
					},
				},
			},
		}
		_, err := v.ValidateCreate(context.Background(), policy)
		if err != nil {
			t.Fatalf("unexpected validation error for SameSite=%s: %v", sameSite, err)
		}
	}
}
