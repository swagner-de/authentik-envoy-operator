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
	"fmt"
	"slices"

	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	v1alpha1 "github.com/authentik-envoy-operator/authentik-envoy-operator/api/v1alpha1"
)

// SetupOIDCPolicyWebhookWithManager registers the webhook for OIDCPolicy in the manager.
func SetupOIDCPolicyWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &v1alpha1.OIDCPolicy{}).
		WithValidator(&OIDCPolicyCustomValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-authentik-envoy-operator-io-v1alpha1-oidcpolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=authentik-envoy-operator.io,resources=oidcpolicies,verbs=create;update,versions=v1alpha1,name=voidcpolicy-v1alpha1.kb.io,admissionReviewVersions=v1

// OIDCPolicyCustomValidator struct is responsible for validating the OIDCPolicy resource
// when it is created, updated, or deleted.
//
// +kubebuilder:object:generate=false
type OIDCPolicyCustomValidator struct{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type OIDCPolicy.
func (v *OIDCPolicyCustomValidator) ValidateCreate(_ context.Context, obj *v1alpha1.OIDCPolicy) (admission.Warnings, error) {
	return validateOIDCPolicy(obj)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type OIDCPolicy.
func (v *OIDCPolicyCustomValidator) ValidateUpdate(_ context.Context, _, newObj *v1alpha1.OIDCPolicy) (admission.Warnings, error) {
	return validateOIDCPolicy(newObj)
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type OIDCPolicy.
func (v *OIDCPolicyCustomValidator) ValidateDelete(_ context.Context, _ *v1alpha1.OIDCPolicy) (admission.Warnings, error) {
	return nil, nil
}

func validateOIDCPolicy(policy *v1alpha1.OIDCPolicy) (admission.Warnings, error) {
	var allErrs field.ErrorList
	specPath := field.NewPath("spec")

	if len(policy.Spec.TargetRefs) == 0 {
		allErrs = append(allErrs, field.Required(specPath.Child("targetRefs"), "at least one targetRef is required"))
	}

	oidcPath := specPath.Child("oidc")

	if len(policy.Spec.OIDC.AllowedGroups) == 0 {
		allErrs = append(allErrs, field.Required(oidcPath.Child("allowedGroups"), "at least one group is required"))
	}

	if !slices.Contains(policy.Spec.OIDC.Scopes, "openid") {
		allErrs = append(allErrs, field.Invalid(oidcPath.Child("scopes"), policy.Spec.OIDC.Scopes, "must contain 'openid'"))
	}

	if policy.Spec.OIDC.CookieConfig != nil && policy.Spec.OIDC.CookieConfig.SameSite != "" {
		validSameSite := []string{"Lax", "Strict", "None"}
		if !slices.Contains(validSameSite, policy.Spec.OIDC.CookieConfig.SameSite) {
			allErrs = append(allErrs, field.Invalid(
				oidcPath.Child("cookieConfig", "sameSite"),
				policy.Spec.OIDC.CookieConfig.SameSite,
				fmt.Sprintf("must be one of: %v", validSameSite),
			))
		}
	}

	if len(allErrs) > 0 {
		return nil, allErrs.ToAggregate()
	}
	return nil, nil
}
