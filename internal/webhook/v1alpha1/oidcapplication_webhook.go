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
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	v1alpha1 "github.com/swagner-de/authentik-envoy-operator/api/v1alpha1"
)

// SetupOIDCApplicationWebhookWithManager registers the webhook for OIDCApplication in the manager.
func SetupOIDCApplicationWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &v1alpha1.OIDCApplication{}).
		WithValidator(&OIDCApplicationCustomValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-authentik-envoy-operator-io-v1alpha1-oidcapplication,mutating=false,failurePolicy=fail,sideEffects=None,groups=authentik-envoy-operator.io,resources=oidcapplications,verbs=create;update,versions=v1alpha1,name=voidcapplication-v1alpha1.kb.io,admissionReviewVersions=v1

// OIDCApplicationCustomValidator struct is responsible for validating the OIDCApplication resource
// when it is created, updated, or deleted.
//
// +kubebuilder:object:generate=false
type OIDCApplicationCustomValidator struct{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type OIDCApplication.
func (v *OIDCApplicationCustomValidator) ValidateCreate(_ context.Context, obj *v1alpha1.OIDCApplication) (admission.Warnings, error) {
	return validateOIDCApplication(obj)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type OIDCApplication.
func (v *OIDCApplicationCustomValidator) ValidateUpdate(_ context.Context, oldObj, newObj *v1alpha1.OIDCApplication) (admission.Warnings, error) {
	if oldObj.EffectiveSlug() != newObj.EffectiveSlug() {
		return nil, invalidOIDCApplication(newObj, field.ErrorList{
			field.Forbidden(field.NewPath("spec", "slug"), "slug is immutable"),
		})
	}
	return validateOIDCApplication(newObj)
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type OIDCApplication.
func (v *OIDCApplicationCustomValidator) ValidateDelete(_ context.Context, _ *v1alpha1.OIDCApplication) (admission.Warnings, error) {
	return nil, nil
}

func validateOIDCApplication(app *v1alpha1.OIDCApplication) (admission.Warnings, error) {
	var allErrs field.ErrorList
	specPath := field.NewPath("spec")

	// The effective slug keys the Authentik objects; Authentik bounds it at 50
	// chars. The CRD pattern/length only covers an explicit spec.slug, so guard
	// the derived "<namespace>-<name>" default here too.
	if slug := app.EffectiveSlug(); len(slug) > 50 {
		allErrs = append(allErrs, field.Invalid(specPath.Child("slug"), slug,
			"effective slug exceeds 50 characters; set a shorter spec.slug"))
	}

	if len(app.Spec.Groups) == 0 {
		allErrs = append(allErrs, field.Required(specPath.Child("groups"), "at least one group is required"))
	}

	if len(app.Spec.Scopes) > 0 && !slices.Contains(app.Spec.Scopes, "openid") {
		allErrs = append(allErrs, field.Invalid(specPath.Child("scopes"), app.Spec.Scopes, "must contain 'openid'"))
	}

	secretTemplatePath := specPath.Child("secretTemplate")
	for key := range app.Spec.SecretTemplate {
		for _, detail := range validation.IsConfigMapKey(key) {
			allErrs = append(allErrs, field.Invalid(secretTemplatePath.Key(key), key, detail))
		}
	}

	if len(app.Spec.SecretTemplate) > 0 {
		secretName := app.EffectiveSecretName()
		if details := validation.IsDNS1123Subdomain(secretName); len(details) > 0 {
			path := specPath.Child("secretName")
			detail := strings.Join(details, ", ")
			if app.Spec.SecretName == "" {
				path = field.NewPath("metadata", "name")
				detail = fmt.Sprintf("derived Secret name %q with the -oidc suffix is invalid: %s", secretName, detail)
			}
			allErrs = append(allErrs, field.Invalid(path, secretName, detail))
		}
	}

	if len(app.Spec.TargetRefs) > 0 {
		secretName := app.EnvoySecretName()
		if details := validation.IsDNS1123Subdomain(secretName); len(details) > 0 {
			allErrs = append(allErrs, field.Invalid(
				field.NewPath("metadata", "name"),
				secretName,
				fmt.Sprintf("derived Secret name %q with the -envoy-oidc suffix is invalid: %s", secretName, strings.Join(details, ", ")),
			))
		}
	}

	if len(app.Spec.SecretTemplate) > 0 && len(app.Spec.TargetRefs) > 0 && app.EffectiveSecretName() == app.EnvoySecretName() {
		allErrs = append(allErrs, field.Invalid(
			specPath.Child("secretName"),
			app.EffectiveSecretName(),
			"application Secret name must differ from the Envoy Secret name",
		))
	}

	if app.Spec.CookieConfig != nil && app.Spec.CookieConfig.SameSite != "" {
		validSameSite := []string{"Lax", "Strict", "None"}
		if !slices.Contains(validSameSite, app.Spec.CookieConfig.SameSite) {
			allErrs = append(allErrs, field.Invalid(
				specPath.Child("cookieConfig", "sameSite"),
				app.Spec.CookieConfig.SameSite,
				fmt.Sprintf("must be one of: %v", validSameSite),
			))
		}
	}

	// Only HTTPRoute (gateway.networking.k8s.io) targetRefs are implemented; reject
	// anything else rather than silently treating it as an HTTPRoute.
	for i, tr := range app.Spec.TargetRefs {
		group := tr.Group
		if group == "" {
			group = "gateway.networking.k8s.io"
		}
		kind := tr.Kind
		if kind == "" {
			kind = "HTTPRoute"
		}
		if group != "gateway.networking.k8s.io" || kind != "HTTPRoute" {
			allErrs = append(allErrs, field.Invalid(
				specPath.Child("targetRefs").Index(i),
				fmt.Sprintf("%s/%s", group, kind),
				"only gateway.networking.k8s.io/HTTPRoute target references are supported",
			))
		}
	}

	if len(allErrs) > 0 {
		return nil, invalidOIDCApplication(app, allErrs)
	}
	return nil, nil
}

func invalidOIDCApplication(app *v1alpha1.OIDCApplication, errs field.ErrorList) error {
	return apierrors.NewInvalid(v1alpha1.GroupVersion.WithKind("OIDCApplication").GroupKind(), app.Name, errs)
}
