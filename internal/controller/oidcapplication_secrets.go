package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	v1alpha1 "github.com/authentik-envoy-operator/authentik-envoy-operator/api/v1alpha1"
)

const (
	secretRoleLabel       = "authentik-envoy-operator.io/secret-role"
	secretRoleApplication = "application"
	secretRoleEnvoy       = "envoy"
)

func (r *OIDCApplicationReconciler) reconcileSecrets(
	ctx context.Context,
	app *v1alpha1.OIDCApplication,
	templateData secretTemplateData,
) (string, string, error) {
	applicationSecretName := ""
	if len(app.Spec.SecretTemplate) > 0 {
		applicationSecretName = app.EffectiveSecretName()
	}
	envoySecretName := ""
	if len(app.Spec.TargetRefs) > 0 {
		envoySecretName = app.EnvoySecretName()
	}
	if applicationSecretName != "" && applicationSecretName == envoySecretName {
		return "", "", fmt.Errorf("application and Envoy Secret names both resolve to %q", applicationSecretName)
	}
	isDesiredSecret := func(name string) bool {
		return name != "" && (name == applicationSecretName || name == envoySecretName)
	}

	desiredApplication, err := r.getSecret(ctx, app.Namespace, applicationSecretName)
	if err != nil {
		return "", "", err
	}
	var existingEnvoy *corev1.Secret
	if envoySecretName != "" {
		existingEnvoy, err = r.getSecret(ctx, app.Namespace, envoySecretName)
		if err != nil {
			return "", "", err
		}
	}

	var previousApplication *corev1.Secret
	if app.Status.SecretName != "" && (desiredApplication == nil || app.Status.SecretName != applicationSecretName) {
		previousApplication, err = r.getSecret(ctx, app.Namespace, app.Status.SecretName)
		if err != nil {
			return "", "", err
		}
	} else {
		previousApplication = desiredApplication
	}
	if previousApplication != nil && !metav1.IsControlledBy(previousApplication, app) {
		previousApplication = nil
	}

	var applicationData map[string][]byte
	if applicationSecretName != "" {
		var previousData map[string][]byte
		if desiredApplication != nil && metav1.IsControlledBy(desiredApplication, app) {
			previousData = desiredApplication.Data
		} else if previousApplication != nil {
			previousData = previousApplication.Data
		}
		applicationData, err = renderSecretTemplate(app.Spec.SecretTemplate, templateData, previousData)
		if err != nil {
			return "", "", fmt.Errorf("rendering application Secret %q: %w", applicationSecretName, err)
		}
	}

	var envoyData map[string][]byte
	if envoySecretName != "" {
		envoyClientSecret := templateData.ClientSecret
		if envoyClientSecret == "" && existingEnvoy != nil && metav1.IsControlledBy(existingEnvoy, app) {
			envoyClientSecret = string(existingEnvoy.Data["client-secret"])
		}
		if envoyClientSecret == "" {
			return "", "", fmt.Errorf("rendering Envoy Secret %q key %q: client secret is unavailable and no previous value exists", envoySecretName, "client-secret")
		}
		envoyData = map[string][]byte{"client-secret": []byte(envoyClientSecret)}
	}

	if err := r.validateSecretOwnership(app, desiredApplication, applicationSecretName); err != nil {
		return "", "", err
	}
	if err := r.validateSecretOwnership(app, existingEnvoy, envoySecretName); err != nil {
		return "", "", err
	}

	if applicationSecretName != "" {
		if err := r.writeSecret(ctx, app, applicationSecretName, secretRoleApplication, applicationData); err != nil {
			return "", "", err
		}
	}
	if envoySecretName != "" {
		if err := r.writeSecret(ctx, app, envoySecretName, secretRoleEnvoy, envoyData); err != nil {
			return "", "", err
		}
	}

	if err := r.deleteStaleSecrets(ctx, app, isDesiredSecret); err != nil {
		return "", "", err
	}

	return applicationSecretName, envoySecretName, nil
}

func (r *OIDCApplicationReconciler) getSecret(ctx context.Context, namespace, name string) (*corev1.Secret, error) {
	if name == "" {
		return nil, nil
	}
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading Secret %q: %w", name, err)
	}
	return secret, nil
}

func (r *OIDCApplicationReconciler) validateSecretOwnership(app *v1alpha1.OIDCApplication, secret *corev1.Secret, name string) error {
	if secret == nil || name == "" {
		return nil
	}
	copy := secret.DeepCopy()
	if err := controllerutil.SetControllerReference(app, copy, r.Scheme); err != nil {
		return fmt.Errorf("Secret %q cannot be controlled by OIDCApplication %q: %w", name, app.Name, err)
	}
	return nil
}

func (r *OIDCApplicationReconciler) writeSecret(ctx context.Context, app *v1alpha1.OIDCApplication, name, role string, data map[string][]byte) error {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: app.Namespace}}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		secret.Data = data
		if secret.Labels == nil {
			secret.Labels = make(map[string]string)
		}
		secret.Labels[secretRoleLabel] = role
		return controllerutil.SetControllerReference(app, secret, r.Scheme)
	}); err != nil {
		return fmt.Errorf("writing Secret %q failed", name)
	}
	return nil
}

func (r *OIDCApplicationReconciler) deleteStaleSecrets(
	ctx context.Context,
	app *v1alpha1.OIDCApplication,
	isDesiredSecret func(string) bool,
) error {
	// Explicit names cover legacy/status-tracked application Secrets and the
	// fixed Envoy Secret even if they predate role labels.
	candidates := make(map[string]bool)
	if app.Status.SecretName != "" && !isDesiredSecret(app.Status.SecretName) {
		candidates[app.Status.SecretName] = false
	}
	envoySecretName := app.EnvoySecretName()
	if !isDesiredSecret(envoySecretName) {
		candidates[envoySecretName] = false
	}

	// Discovery is deliberately limited to application-role Secrets created by
	// this feature. The bool records that the role must still match after GET.
	var secrets corev1.SecretList
	if err := r.List(ctx, &secrets,
		client.InNamespace(app.Namespace),
		client.MatchingLabels{secretRoleLabel: secretRoleApplication},
	); err != nil {
		return fmt.Errorf("listing Secrets: %w", err)
	}
	for i := range secrets.Items {
		secret := &secrets.Items[i]
		if isDesiredSecret(secret.Name) || !metav1.IsControlledBy(secret, app) {
			continue
		}
		if _, explicitlyNamed := candidates[secret.Name]; !explicitlyNamed {
			candidates[secret.Name] = true
		}
	}

	for name, requireApplicationRole := range candidates {
		current := &corev1.Secret{}
		key := types.NamespacedName{Name: name, Namespace: app.Namespace}
		if err := r.Get(ctx, key, current); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return fmt.Errorf("reading stale Secret %q: %w", name, err)
		}
		if isDesiredSecret(current.Name) || !metav1.IsControlledBy(current, app) {
			continue
		}
		if requireApplicationRole && current.Labels[secretRoleLabel] != secretRoleApplication {
			continue
		}
		if err := r.Delete(ctx, current, client.Preconditions{
			UID:             &current.UID,
			ResourceVersion: &current.ResourceVersion,
		}); client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("deleting Secret %q failed", name)
		}
	}
	return nil
}
