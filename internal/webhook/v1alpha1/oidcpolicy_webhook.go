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

	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	authentikenvoyoperatoriov1alpha1 "github.com/authentik-envoy-operator/authentik-envoy-operator/api/v1alpha1"
)

// nolint:unused
// log is for logging in this package.
var oidcpolicylog = logf.Log.WithName("oidcpolicy-resource")

// SetupOIDCPolicyWebhookWithManager registers the webhook for OIDCPolicy in the manager.
func SetupOIDCPolicyWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &authentikenvoyoperatoriov1alpha1.OIDCPolicy{}).
		WithValidator(&OIDCPolicyCustomValidator{}).
		Complete()
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// NOTE: If you want to customise the 'path', use the flags '--defaulting-path' or '--validation-path'.
// +kubebuilder:webhook:path=/validate-authentik-envoy-operator-io-v1alpha1-oidcpolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=authentik-envoy-operator.io,resources=oidcpolicies,verbs=create;update,versions=v1alpha1,name=voidcpolicy-v1alpha1.kb.io,admissionReviewVersions=v1

// OIDCPolicyCustomValidator struct is responsible for validating the OIDCPolicy resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type OIDCPolicyCustomValidator struct {
	// TODO(user): Add more fields as needed for validation
}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type OIDCPolicy.
func (v *OIDCPolicyCustomValidator) ValidateCreate(_ context.Context, obj *authentikenvoyoperatoriov1alpha1.OIDCPolicy) (admission.Warnings, error) {
	oidcpolicylog.Info("Validation for OIDCPolicy upon creation", "name", obj.GetName())

	// TODO(user): fill in your validation logic upon object creation.

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type OIDCPolicy.
func (v *OIDCPolicyCustomValidator) ValidateUpdate(_ context.Context, oldObj, newObj *authentikenvoyoperatoriov1alpha1.OIDCPolicy) (admission.Warnings, error) {
	oidcpolicylog.Info("Validation for OIDCPolicy upon update", "name", newObj.GetName())

	// TODO(user): fill in your validation logic upon object update.

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type OIDCPolicy.
func (v *OIDCPolicyCustomValidator) ValidateDelete(_ context.Context, obj *authentikenvoyoperatoriov1alpha1.OIDCPolicy) (admission.Warnings, error) {
	oidcpolicylog.Info("Validation for OIDCPolicy upon deletion", "name", obj.GetName())

	// TODO(user): fill in your validation logic upon object deletion.

	return nil, nil
}
