package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	egv1alpha1 "github.com/envoyproxy/gateway/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/authentik-envoy-operator/authentik-envoy-operator/api/v1alpha1"
	"github.com/authentik-envoy-operator/authentik-envoy-operator/internal/authentik"
	appmetrics "github.com/authentik-envoy-operator/authentik-envoy-operator/internal/metrics"
)

const (
	ConditionReady = "Ready"
	finalizerName  = "authentik-envoy-operator.io/cleanup"
)

// OIDCPolicyReconciler reconciles OIDCPolicy resources.
type OIDCPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=authentik-envoy-operator.io,resources=oidcpolicies,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=authentik-envoy-operator.io,resources=oidcpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=authentik-envoy-operator.io,resources=oidcpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=authentik-envoy-operator.io,resources=authentikproviders,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.envoyproxy.io,resources=securitypolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func (r *OIDCPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	startTime := time.Now()
	defer func() {
		appmetrics.ReconcileDuration.WithLabelValues(req.Name, req.Namespace).Observe(time.Since(startTime).Seconds())
	}()

	var policy v1alpha1.OIDCPolicy
	if err := r.Get(ctx, req.NamespacedName, &policy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Handle deletion
	if !policy.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&policy, finalizerName) {
			if err := r.cleanup(ctx, &policy); err != nil {
				log.Error(err, "Cleanup failed")
				return ctrl.Result{}, err
			}
			controllerutil.RemoveFinalizer(&policy, finalizerName)
			if err := r.Update(ctx, &policy); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer
	if !controllerutil.ContainsFinalizer(&policy, finalizerName) {
		controllerutil.AddFinalizer(&policy, finalizerName)
		return ctrl.Result{}, r.Update(ctx, &policy)
	}

	// Fetch AuthentikProvider
	var provider v1alpha1.AuthentikProvider
	if err := r.Get(ctx, types.NamespacedName{Name: policy.Spec.ProviderRef.Name}, &provider); err != nil {
		r.setCondition(&policy, metav1.ConditionFalse, "ProviderNotFound", fmt.Sprintf("AuthentikProvider %q not found", policy.Spec.ProviderRef.Name))
		appmetrics.PolicyStatus.WithLabelValues(req.Name, req.Namespace).Set(0)
		if err := r.Status().Update(ctx, &policy); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Check provider is connected
	connected := meta.FindStatusCondition(provider.Status.Conditions, ConditionConnected)
	if connected == nil || connected.Status != metav1.ConditionTrue {
		r.setCondition(&policy, metav1.ConditionFalse, "ProviderNotConnected", "AuthentikProvider is not connected")
		appmetrics.PolicyStatus.WithLabelValues(req.Name, req.Namespace).Set(0)
		if err := r.Status().Update(ctx, &policy); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Build Authentik client
	var secret corev1.Secret
	secretRef := types.NamespacedName{
		Name:      provider.Spec.APITokenSecretRef.Name,
		Namespace: provider.Spec.APITokenSecretRef.Namespace,
	}
	if err := r.Get(ctx, secretRef, &secret); err != nil {
		r.setCondition(&policy, metav1.ConditionFalse, "SecretNotFound", "API token secret not found")
		appmetrics.PolicyStatus.WithLabelValues(req.Name, req.Namespace).Set(0)
		if err := r.Status().Update(ctx, &policy); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}
	token := string(secret.Data[provider.Spec.APITokenSecretRef.Key])
	apiClient := authentik.NewClient(provider.Spec.Host, token)

	// Derive identifiers
	appSlug := fmt.Sprintf("%s-%s", policy.Namespace, policy.Name)
	clientID := appSlug

	// Step 1: Resolve groups
	groupUUIDs := make(map[string]string)
	for _, groupName := range policy.Spec.OIDC.AllowedGroups {
		group, err := apiClient.GetGroupByName(ctx, groupName)
		if err != nil {
			r.setCondition(&policy, metav1.ConditionFalse, "GroupNotFound", fmt.Sprintf("group %q not found in Authentik", groupName))
			appmetrics.PolicyStatus.WithLabelValues(req.Name, req.Namespace).Set(0)
			appmetrics.ReconcileErrors.WithLabelValues(req.Name, req.Namespace, "group_not_found").Inc()
			if err := r.Status().Update(ctx, &policy); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		groupUUIDs[groupName] = group.PK
	}

	// Step 1b: Resolve signing key name to UUID
	signingKeyPair, err := apiClient.GetCertificateKeyPairByName(ctx, policy.Spec.OIDC.SigningKey)
	if err != nil {
		r.setCondition(&policy, metav1.ConditionFalse, "SigningKeyNotFound", fmt.Sprintf("signing key %q not found in Authentik", policy.Spec.OIDC.SigningKey))
		appmetrics.PolicyStatus.WithLabelValues(req.Name, req.Namespace).Set(0)
		if err := r.Status().Update(ctx, &policy); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Step 1c: Resolve property mapping names to UUIDs
	var propertyMappingUUIDs []string
	for _, mappingName := range policy.Spec.OIDC.PropertyMappings {
		mapping, err := apiClient.GetScopeMappingByName(ctx, mappingName)
		if err != nil {
			r.setCondition(&policy, metav1.ConditionFalse, "PropertyMappingNotFound", fmt.Sprintf("property mapping %q not found in Authentik", mappingName))
			appmetrics.PolicyStatus.WithLabelValues(req.Name, req.Namespace).Set(0)
			if err := r.Status().Update(ctx, &policy); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		propertyMappingUUIDs = append(propertyMappingUUIDs, mapping.PK)
	}

	// Step 2: Resolve redirect URIs from HTTPRoute hostnames
	var redirectURIs []authentik.RedirectURI
	for _, targetRef := range policy.Spec.TargetRefs {
		var httpRoute gwapiv1.HTTPRoute
		if err := r.Get(ctx, types.NamespacedName{Name: targetRef.Name, Namespace: policy.Namespace}, &httpRoute); err != nil {
			r.setCondition(&policy, metav1.ConditionFalse, "HTTPRouteNotFound", fmt.Sprintf("HTTPRoute %q not found", targetRef.Name))
			appmetrics.PolicyStatus.WithLabelValues(req.Name, req.Namespace).Set(0)
			if err := r.Status().Update(ctx, &policy); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		for _, hostname := range httpRoute.Spec.Hostnames {
			redirectURIs = append(redirectURIs, authentik.RedirectURI{
				MatchingMode:    "strict",
				URL:             fmt.Sprintf("https://%s/oauth2/callback", hostname),
				RedirectURIType: "authorization",
			})
		}
	}

	// Step 3: Create/Update Authentik OAuth2 Provider
	providerReq := authentik.OAuth2ProviderRequest{
		Name:              appSlug,
		AuthorizationFlow: provider.Status.AuthorizationFlowUID,
		InvalidationFlow:  provider.Status.InvalidationFlowUID,
		ClientType:        "confidential",
		ClientID:          clientID,
		RedirectURIs:      redirectURIs,
		GrantTypes:        []string{"authorization_code", "refresh_token"},
		SigningKey:         signingKeyPair.PK,
		PropertyMappings:  propertyMappingUUIDs,
	}

	var oauthProvider *authentik.OAuth2Provider
	if policy.Status.Authentik != nil && policy.Status.Authentik.ProviderID > 0 {
		current, err := apiClient.GetProvider(ctx, policy.Status.Authentik.ProviderID)
		if err != nil {
			if !isNotFound(err) {
				appmetrics.ReconcileErrors.WithLabelValues(req.Name, req.Namespace, "provider_get").Inc()
				return ctrl.Result{}, fmt.Errorf("getting Authentik provider: %w", err)
			}
			// Provider was deleted out-of-band, recreate it
			current = nil
		}
		if current != nil {
			if authentik.ProviderNeedsUpdate(current, providerReq) {
				oauthProvider, err = apiClient.UpdateProvider(ctx, policy.Status.Authentik.ProviderID, providerReq)
				if err != nil {
					appmetrics.ReconcileErrors.WithLabelValues(req.Name, req.Namespace, "provider_update").Inc()
					return ctrl.Result{}, fmt.Errorf("updating Authentik provider: %w", err)
				}
			} else {
				oauthProvider = current
			}
		}
	}
	if oauthProvider == nil {
		var err error
		oauthProvider, err = apiClient.CreateProvider(ctx, providerReq)
		if err != nil {
			appmetrics.ReconcileErrors.WithLabelValues(req.Name, req.Namespace, "provider_create").Inc()
			return ctrl.Result{}, fmt.Errorf("creating Authentik provider: %w", err)
		}
	}

	// Step 3: Create/Update Authentik Application
	appReq := authentik.ApplicationRequest{
		Name:             appSlug,
		Slug:             appSlug,
		Provider:         oauthProvider.PK,
		PolicyEngineMode: "any",
	}

	var app *authentik.Application
	if policy.Status.Authentik != nil && policy.Status.Authentik.ApplicationSlug != "" {
		current, err := apiClient.GetApplication(ctx, policy.Status.Authentik.ApplicationSlug)
		if err != nil {
			if !isNotFound(err) {
				appmetrics.ReconcileErrors.WithLabelValues(req.Name, req.Namespace, "application_get").Inc()
				return ctrl.Result{}, fmt.Errorf("getting Authentik application: %w", err)
			}
			log.Info("Application not found, will create", "slug", policy.Status.Authentik.ApplicationSlug)
		} else if authentik.ApplicationNeedsUpdate(current, appReq) {
			app, err = apiClient.UpdateApplication(ctx, policy.Status.Authentik.ApplicationSlug, appReq)
			if err != nil {
				appmetrics.ReconcileErrors.WithLabelValues(req.Name, req.Namespace, "application_update").Inc()
				return ctrl.Result{}, fmt.Errorf("updating Authentik application: %w", err)
			}
		} else {
			app = current
		}
	}
	if app == nil {
		var err error
		app, err = apiClient.CreateApplication(ctx, appReq)
		if err != nil {
			appmetrics.ReconcileErrors.WithLabelValues(req.Name, req.Namespace, "application_create").Inc()
			return ctrl.Result{}, fmt.Errorf("creating Authentik application: %w", err)
		}
	}

	// Step 4: Reconcile PolicyBindings
	// Compare actual bindings in Authentik against desired state
	desiredGroupUUIDs := make([]string, 0, len(policy.Spec.OIDC.AllowedGroups))
	for _, groupName := range policy.Spec.OIDC.AllowedGroups {
		desiredGroupUUIDs = append(desiredGroupUUIDs, groupUUIDs[groupName])
	}

	var bindingIDs []string
	needsBindingRecreate := true

	currentBindings, err := apiClient.ListPolicyBindings(ctx, app.PK)
	if err != nil {
		log.Error(err, "failed to list policy bindings, will recreate")
	} else {
		currentGroupUUIDs := make([]string, 0, len(currentBindings))
		for _, b := range currentBindings {
			currentGroupUUIDs = append(currentGroupUUIDs, b.Group)
		}
		if authentik.StringSetEqual(currentGroupUUIDs, desiredGroupUUIDs) {
			needsBindingRecreate = false
			for _, b := range currentBindings {
				bindingIDs = append(bindingIDs, b.PK)
			}
		}
	}

	if needsBindingRecreate {
		log.Info("Recreating policy bindings", "reason", "groups changed or no existing bindings")
		// Delete stale bindings
		for _, b := range currentBindings {
			if err := apiClient.DeletePolicyBinding(ctx, b.PK); err != nil {
				log.Error(err, "failed to delete stale policy binding", "id", b.PK)
			}
		}

		// Create fresh bindings
		for i, groupName := range policy.Spec.OIDC.AllowedGroups {
			binding, err := apiClient.CreatePolicyBinding(ctx, authentik.PolicyBindingRequest{
				Target:  app.PK,
				Group:   groupUUIDs[groupName],
				Order:   i,
				Enabled: true,
			})
			if err != nil {
				appmetrics.ReconcileErrors.WithLabelValues(req.Name, req.Namespace, "binding_create").Inc()
				log.Error(err, "failed to create policy binding", "group", groupName)
				continue
			}
			bindingIDs = append(bindingIDs, binding.PK)
		}

		// Check if any bindings failed
		if len(bindingIDs) != len(policy.Spec.OIDC.AllowedGroups) {
			r.setCondition(&policy, metav1.ConditionFalse, "BindingsFailed", "one or more policy bindings failed to create")
			appmetrics.PolicyStatus.WithLabelValues(req.Name, req.Namespace).Set(0)
			if err := r.Status().Update(ctx, &policy); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
	} else {
		log.V(1).Info("Policy bindings unchanged, skipping recreation")
		bindingIDs = policy.Status.Authentik.PolicyBindingIDs
	}

	// Step 5: Sync client secret to K8s
	secretName := fmt.Sprintf("%s-client-secret", policy.Name)
	clientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: policy.Namespace,
		},
	}
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, clientSecret, func() error {
		clientSecret.Data = map[string][]byte{
			"client-secret": []byte(oauthProvider.ClientSecret),
		}
		return controllerutil.SetControllerReference(&policy, clientSecret, r.Scheme)
	})
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("syncing client secret: %w", err)
	}

	// Step 6: Create/Update SecurityPolicies (one per targetRef)
	var secPolicyRefs []v1alpha1.SecurityPolicyRef
	params := SecurityPolicyParams{
		AuthentikHost:   provider.Spec.Host,
		ApplicationSlug: appSlug,
		ClientID:        clientID,
		SecretName:      secretName,
	}

	// Delete orphaned SecurityPolicies from previous reconcile
	desiredNames := make(map[string]bool)
	for _, targetRef := range policy.Spec.TargetRefs {
		desiredNames[fmt.Sprintf("%s-%s", policy.Name, targetRef.Name)] = true
	}
	for _, ref := range policy.Status.SecurityPolicies {
		if !desiredNames[ref.Name] {
			stale := &egv1alpha1.SecurityPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ref.Name,
					Namespace: policy.Namespace,
				},
			}
			if err := r.Delete(ctx, stale); client.IgnoreNotFound(err) != nil {
				log.Error(err, "failed to delete orphaned SecurityPolicy", "name", ref.Name)
			}
		}
	}

	for _, targetRef := range policy.Spec.TargetRefs {
		desired := BuildSecurityPolicy(&policy, targetRef, params)

		existing := &egv1alpha1.SecurityPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      desired.Name,
				Namespace: desired.Namespace,
			},
		}
		_, err := controllerutil.CreateOrUpdate(ctx, r.Client, existing, func() error {
			existing.Spec = desired.Spec
			existing.OwnerReferences = desired.OwnerReferences
			return nil
		})
		if err != nil {
			appmetrics.ReconcileErrors.WithLabelValues(req.Name, req.Namespace, "securitypolicy_sync").Inc()
			return ctrl.Result{}, fmt.Errorf("syncing SecurityPolicy %s: %w", desired.Name, err)
		}

		secPolicyRefs = append(secPolicyRefs, v1alpha1.SecurityPolicyRef{
			Name:        desired.Name,
			TargetRoute: targetRef.Name,
		})
	}

	// Step 7: Update status
	policy.Status.Authentik = &v1alpha1.AuthentikStatus{
		ProviderID:       oauthProvider.PK,
		ClientID:         clientID,
		ApplicationSlug:  appSlug,
		ApplicationID:    app.PK,
		PolicyBindingIDs: bindingIDs,
		BoundGroups:      policy.Spec.OIDC.AllowedGroups,
	}
	policy.Status.SecurityPolicies = secPolicyRefs
	policy.Status.SecretName = secretName
	r.setCondition(&policy, metav1.ConditionTrue, "Reconciled", "All resources created successfully")
	appmetrics.PolicyStatus.WithLabelValues(req.Name, req.Namespace).Set(1)

	if err := r.Status().Update(ctx, &policy); err != nil {
		return ctrl.Result{}, err
	}

	log.Info("OIDCPolicy reconciled", "appSlug", appSlug)
	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

func (r *OIDCPolicyReconciler) cleanup(ctx context.Context, policy *v1alpha1.OIDCPolicy) error {
	log := log.FromContext(ctx)

	if policy.Status.Authentik == nil {
		return nil
	}

	// Get AuthentikProvider for API access
	var provider v1alpha1.AuthentikProvider
	if err := r.Get(ctx, types.NamespacedName{Name: policy.Spec.ProviderRef.Name}, &provider); err != nil {
		log.Error(err, "cannot reach AuthentikProvider for cleanup, skipping Authentik resource deletion")
		return nil
	}

	var secret corev1.Secret
	secretRef := types.NamespacedName{
		Name:      provider.Spec.APITokenSecretRef.Name,
		Namespace: provider.Spec.APITokenSecretRef.Namespace,
	}
	if err := r.Get(ctx, secretRef, &secret); err != nil {
		log.Error(err, "cannot read API token for cleanup")
		return nil
	}
	token := string(secret.Data[provider.Spec.APITokenSecretRef.Key])
	apiClient := authentik.NewClient(provider.Spec.Host, token)

	// Delete policy bindings
	for _, bindingID := range policy.Status.Authentik.PolicyBindingIDs {
		if err := apiClient.DeletePolicyBinding(ctx, bindingID); err != nil {
			if !isNotFound(err) {
				return fmt.Errorf("deleting policy binding %s: %w", bindingID, err)
			}
		}
	}

	// Delete application
	if policy.Status.Authentik.ApplicationSlug != "" {
		if err := apiClient.DeleteApplication(ctx, policy.Status.Authentik.ApplicationSlug); err != nil {
			if !isNotFound(err) {
				return fmt.Errorf("deleting application %s: %w", policy.Status.Authentik.ApplicationSlug, err)
			}
		}
	}

	// Delete provider
	if policy.Status.Authentik.ProviderID > 0 {
		if err := apiClient.DeleteProvider(ctx, policy.Status.Authentik.ProviderID); err != nil {
			if !isNotFound(err) {
				return fmt.Errorf("deleting provider %d: %w", policy.Status.Authentik.ProviderID, err)
			}
		}
	}

	return nil
}

func (r *OIDCPolicyReconciler) setCondition(policy *v1alpha1.OIDCPolicy, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
		Type:               ConditionReady,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})
}

func (r *OIDCPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.OIDCPolicy{}).
		Owns(&egv1alpha1.SecurityPolicy{}).
		Watches(&v1alpha1.AuthentikProvider{}, handler.EnqueueRequestsFromMapFunc(r.mapProviderToPolicies)).
		Watches(&gwapiv1.HTTPRoute{}, handler.EnqueueRequestsFromMapFunc(r.mapHTTPRouteToPolicies)).
		Complete(r)
}

func (r *OIDCPolicyReconciler) mapProviderToPolicies(ctx context.Context, obj client.Object) []reconcile.Request {
	var policies v1alpha1.OIDCPolicyList
	if err := r.List(ctx, &policies); err != nil {
		return nil
	}
	var requests []reconcile.Request
	for _, p := range policies.Items {
		if p.Spec.ProviderRef.Name == obj.GetName() {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: p.Name, Namespace: p.Namespace},
			})
		}
	}
	return requests
}

func (r *OIDCPolicyReconciler) mapHTTPRouteToPolicies(ctx context.Context, obj client.Object) []reconcile.Request {
	var policies v1alpha1.OIDCPolicyList
	if err := r.List(ctx, &policies, client.InNamespace(obj.GetNamespace())); err != nil {
		return nil
	}
	var requests []reconcile.Request
	for _, p := range policies.Items {
		for _, ref := range p.Spec.TargetRefs {
			if ref.Name == obj.GetName() {
				requests = append(requests, reconcile.Request{
					NamespacedName: types.NamespacedName{Name: p.Name, Namespace: p.Namespace},
				})
				break
			}
		}
	}
	return requests
}

func isNotFound(err error) bool {
	var apiErr *authentik.APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == 404
}
