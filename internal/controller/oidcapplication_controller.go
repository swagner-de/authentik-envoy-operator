package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
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

// OIDCApplicationReconciler reconciles OIDCApplication resources.
type OIDCApplicationReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=authentik-envoy-operator.io,resources=oidcapplications,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=authentik-envoy-operator.io,resources=oidcapplications/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=authentik-envoy-operator.io,resources=oidcapplications/finalizers,verbs=update
// +kubebuilder:rbac:groups=authentik-envoy-operator.io,resources=authentikproviders,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.envoyproxy.io,resources=securitypolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

//nolint:gocyclo // Reconcile is a linear provisioning pipeline; splitting it would obscure the flow.
func (r *OIDCApplicationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	startTime := time.Now()
	defer func() {
		appmetrics.ReconcileDuration.WithLabelValues(req.Name, req.Namespace).Observe(time.Since(startTime).Seconds())
	}()

	var app v1alpha1.OIDCApplication
	if err := r.Get(ctx, req.NamespacedName, &app); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Handle deletion
	if !app.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&app, finalizerName) {
			if err := r.cleanup(ctx, &app); err != nil {
				log.Error(err, "Cleanup failed")
				return ctrl.Result{}, err
			}
			controllerutil.RemoveFinalizer(&app, finalizerName)
			if err := r.Update(ctx, &app); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer
	if !controllerutil.ContainsFinalizer(&app, finalizerName) {
		controllerutil.AddFinalizer(&app, finalizerName)
		return ctrl.Result{}, r.Update(ctx, &app)
	}

	// Fetch AuthentikProvider
	var provider v1alpha1.AuthentikProvider
	if err := r.Get(ctx, types.NamespacedName{Name: app.Spec.ProviderRef.Name}, &provider); err != nil {
		return r.failRequeue(ctx, &app, req, "ProviderNotFound", fmt.Sprintf("AuthentikProvider %q not found", app.Spec.ProviderRef.Name))
	}

	// Check provider is connected
	connected := meta.FindStatusCondition(provider.Status.Conditions, ConditionConnected)
	if connected == nil || connected.Status != metav1.ConditionTrue {
		return r.failRequeue(ctx, &app, req, "ProviderNotConnected", "AuthentikProvider is not connected")
	}

	// Build Authentik client
	var secret corev1.Secret
	secretRef := types.NamespacedName{
		Name:      provider.Spec.APITokenSecretRef.Name,
		Namespace: provider.Spec.APITokenSecretRef.Namespace,
	}
	if err := r.Get(ctx, secretRef, &secret); err != nil {
		r.setCondition(&app, metav1.ConditionFalse, "SecretNotFound", "API token secret not found")
		appmetrics.PolicyStatus.WithLabelValues(req.Name, req.Namespace).Set(0)
		if err := r.Status().Update(ctx, &app); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}
	token := string(secret.Data[provider.Spec.APITokenSecretRef.Key])
	apiClient := authentik.NewClient(provider.Spec.Host, token)

	// Derive identifiers from helpers.
	slug := app.EffectiveSlug()
	clientID := slug

	// Resolve groups (creating create:true groups when absent).
	groupUUIDs, createdGroups, err := resolveGroups(ctx, apiClient, &app)
	if err != nil {
		appmetrics.ReconcileErrors.WithLabelValues(req.Name, req.Namespace, "group_resolution").Inc()
		return r.failRequeue(ctx, &app, req, "GroupResolutionFailed", err.Error())
	}

	// Resolve signing key name to UUID.
	signingKeyPair, err := apiClient.GetCertificateKeyPairByName(ctx, app.Spec.SigningKey)
	if err != nil {
		return r.failRequeue(ctx, &app, req, "SigningKeyLookupFailed", fmt.Sprintf("looking up signing key %q: %v", app.Spec.SigningKey, err))
	}
	if signingKeyPair == nil {
		return r.failRequeue(ctx, &app, req, "SigningKeyNotFound", fmt.Sprintf("signing key %q not found in Authentik", app.Spec.SigningKey))
	}

	// Resolve property mapping names to UUIDs.
	var propertyMappingUUIDs []string
	for _, mappingName := range app.Spec.PropertyMappings {
		mapping, merr := apiClient.GetScopeMappingByName(ctx, mappingName)
		if merr != nil {
			return r.failRequeue(ctx, &app, req, "PropertyMappingLookupFailed", fmt.Sprintf("looking up property mapping %q: %v", mappingName, merr))
		}
		if mapping == nil {
			return r.failRequeue(ctx, &app, req, "PropertyMappingNotFound", fmt.Sprintf("property mapping %q not found in Authentik", mappingName))
		}
		propertyMappingUUIDs = append(propertyMappingUUIDs, mapping.PK)
	}

	// Build redirect URIs = explicit ∪ route-derived.
	var redirectURIs []authentik.RedirectURI
	for _, u := range app.Spec.RedirectURIs {
		redirectURIs = append(redirectURIs, authentik.RedirectURI{MatchingMode: "strict", URL: u, RedirectURIType: "authorization"})
	}
	host := strings.TrimRight(provider.Spec.Host, "/")
	for _, tr := range app.Spec.TargetRefs {
		var hr gwapiv1.HTTPRoute
		if err := r.Get(ctx, types.NamespacedName{Name: tr.Name, Namespace: app.Namespace}, &hr); err != nil {
			return r.failRequeue(ctx, &app, req, "HTTPRouteNotFound", fmt.Sprintf("HTTPRoute %q not found", tr.Name))
		}
		for _, h := range hr.Spec.Hostnames {
			redirectURIs = append(redirectURIs, authentik.RedirectURI{
				MatchingMode: "strict", URL: fmt.Sprintf("https://%s/oauth2/callback", h), RedirectURIType: "authorization",
			})
		}
	}

	// A fronted app whose routes have no hostnames (and no explicit redirectURIs)
	// would register zero callback URIs, silently breaking OIDC login. Surface it
	// rather than provisioning an unusable provider.
	if len(app.Spec.TargetRefs) > 0 && len(redirectURIs) == 0 {
		return r.failRequeue(ctx, &app, req, "NoRedirectURIs",
			"no redirect URIs derived: targeted HTTPRoute(s) declare no hostnames; set spec.redirectURIs or add hostnames to the route")
	}

	// Build the provider request.
	includeClaims := true
	if app.Spec.IncludeClaimsInIDToken != nil {
		includeClaims = *app.Spec.IncludeClaimsInIDToken
	}
	providerReq := authentik.OAuth2ProviderRequest{
		Name:                   slug,
		AuthorizationFlow:      provider.Status.AuthorizationFlowUID,
		InvalidationFlow:       provider.Status.InvalidationFlowUID,
		ClientType:             "confidential",
		ClientID:               clientID,
		RedirectURIs:           redirectURIs,
		GrantTypes:             []string{"authorization_code", "refresh_token"},
		SigningKey:             signingKeyPair.PK,
		PropertyMappings:       propertyMappingUUIDs,
		SubMode:                app.Spec.SubMode,
		IssuerMode:             "per_provider",
		IncludeClaimsInIDToken: includeClaims,
		AccessTokenValidity:    app.Spec.AccessTokenValidity,
		RefreshTokenValidity:   app.Spec.RefreshTokenValidity,
		AccessCodeValidity:     app.Spec.AccessCodeValidity,
	}

	// Adopt/upsert application keyed on the stable slug, then resolve or create
	// the provider through the app link (avoids leaking orphan providers).
	appReq := authentik.ApplicationRequest{
		Name:             app.EffectiveDisplayName(),
		Slug:             slug,
		PolicyEngineMode: "any",
	}
	if app.Spec.AppMeta != nil {
		appReq.MetaLaunchURL = app.Spec.AppMeta.LaunchURL
		appReq.MetaDescription = app.Spec.AppMeta.Description
		appReq.MetaPublisher = app.Spec.AppMeta.Publisher
		appReq.MetaIcon = app.Spec.AppMeta.Icon
		appReq.OpenInNewTab = app.Spec.AppMeta.OpenInNewTab
		appReq.Group = app.Spec.AppMeta.Group
	}

	current, err := apiClient.GetApplication(ctx, slug)
	if err != nil && !isNotFound(err) {
		appmetrics.ReconcileErrors.WithLabelValues(req.Name, req.Namespace, "application_get").Inc()
		return ctrl.Result{}, fmt.Errorf("getting application: %w", err)
	}
	appExists := current != nil && err == nil

	var oauthProvider *authentik.OAuth2Provider
	if appExists {
		// Application exists → resolve its linked provider by PK.
		oauthProvider, err = apiClient.GetProvider(ctx, current.Provider)
		if err != nil {
			if !isNotFound(err) {
				return ctrl.Result{}, fmt.Errorf("getting linked provider: %w", err)
			}
			oauthProvider = nil // linked provider vanished; recreate below
		}
		if oauthProvider != nil && authentik.ProviderNeedsUpdate(oauthProvider, providerReq) {
			oauthProvider, err = apiClient.UpdateProvider(ctx, oauthProvider.PK, providerReq)
			if err != nil {
				appmetrics.ReconcileErrors.WithLabelValues(req.Name, req.Namespace, "provider_update").Inc()
				return ctrl.Result{}, fmt.Errorf("updating provider: %w", err)
			}
		}
	}
	// No provider yet (fresh app, or linked provider gone): recover orphan by name, else create.
	if oauthProvider == nil {
		orphan, gerr := apiClient.GetProviderByName(ctx, slug)
		if gerr != nil {
			return ctrl.Result{}, fmt.Errorf("looking up provider by name: %w", gerr)
		}
		if orphan != nil {
			if authentik.ProviderNeedsUpdate(orphan, providerReq) {
				oauthProvider, err = apiClient.UpdateProvider(ctx, orphan.PK, providerReq)
				if err != nil {
					return ctrl.Result{}, fmt.Errorf("updating orphan provider: %w", err)
				}
			} else {
				oauthProvider = orphan
			}
		} else {
			oauthProvider, err = apiClient.CreateProvider(ctx, providerReq)
			if err != nil {
				appmetrics.ReconcileErrors.WithLabelValues(req.Name, req.Namespace, "provider_create").Inc()
				return ctrl.Result{}, fmt.Errorf("creating provider: %w", err)
			}
		}
	}

	// Ensure the application exists / is up to date, linked to the provider.
	appReq.Provider = oauthProvider.PK
	var appObj *authentik.Application
	if appExists {
		if authentik.ApplicationNeedsUpdate(current, appReq) {
			appObj, err = apiClient.UpdateApplication(ctx, slug, appReq)
			if err != nil {
				appmetrics.ReconcileErrors.WithLabelValues(req.Name, req.Namespace, "application_update").Inc()
				return ctrl.Result{}, fmt.Errorf("updating application: %w", err)
			}
		} else {
			appObj = current
		}
	}
	if appObj == nil {
		appObj, err = apiClient.CreateApplication(ctx, appReq)
		if err != nil {
			appmetrics.ReconcileErrors.WithLabelValues(req.Name, req.Namespace, "application_create").Inc()
			return ctrl.Result{}, fmt.Errorf("creating application: %w", err)
		}
	}

	// Reconcile policy bindings keyed on the application PK.
	desiredGroupUUIDs := make([]string, 0, len(app.Spec.Groups))
	for _, g := range app.Spec.Groups {
		desiredGroupUUIDs = append(desiredGroupUUIDs, groupUUIDs[g.Name])
	}

	currentBindings, err := apiClient.ListPolicyBindings(ctx, appObj.PK)
	if err != nil {
		appmetrics.ReconcileErrors.WithLabelValues(req.Name, req.Namespace, "binding_list").Inc()
		return ctrl.Result{}, fmt.Errorf("listing policy bindings: %w", err)
	}

	var bindingIDs []string
	currentGroupUUIDs := make([]string, 0, len(currentBindings))
	for _, b := range currentBindings {
		currentGroupUUIDs = append(currentGroupUUIDs, b.Group)
	}
	if authentik.StringSetEqual(currentGroupUUIDs, desiredGroupUUIDs) {
		for _, b := range currentBindings {
			bindingIDs = append(bindingIDs, b.PK)
		}
	} else {
		log.Info("Recreating policy bindings", "reason", "groups changed or no existing bindings")
		for _, b := range currentBindings {
			if err := apiClient.DeletePolicyBinding(ctx, b.PK); err != nil {
				log.Error(err, "failed to delete stale policy binding", "id", b.PK)
			}
		}
		for i, g := range app.Spec.Groups {
			binding, berr := apiClient.CreatePolicyBinding(ctx, authentik.PolicyBindingRequest{
				Target:  appObj.PK,
				Group:   groupUUIDs[g.Name],
				Order:   i,
				Enabled: true,
			})
			if berr != nil {
				appmetrics.ReconcileErrors.WithLabelValues(req.Name, req.Namespace, "binding_create").Inc()
				log.Error(berr, "failed to create policy binding", "group", g.Name)
				continue
			}
			bindingIDs = append(bindingIDs, binding.PK)
		}
		if len(bindingIDs) != len(app.Spec.Groups) {
			return r.failRequeue(ctx, &app, req, "BindingsFailed", "one or more policy bindings failed to create")
		}
	}

	// Discovery data is only needed to render an application Secret. Envoy
	// resources derive their issuer and JWKS URLs from the provider host and slug.
	templateData := secretTemplateData{
		ClientID:     clientID,
		ClientSecret: oauthProvider.ClientSecret,
	}
	if len(app.Spec.SecretTemplate) > 0 {
		issuer := fmt.Sprintf("%s/application/o/%s/", host, slug)
		doc, discoveryErr := apiClient.GetDiscoveryDocument(ctx, issuer)
		if discoveryErr != nil {
			appmetrics.ReconcileErrors.WithLabelValues(req.Name, req.Namespace, "discovery").Inc()
			return ctrl.Result{}, fmt.Errorf("fetching discovery document: %w", discoveryErr)
		}
		templateData.Issuer = doc.Issuer
		templateData.DiscoveryURL = strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
		templateData.AuthorizationEndpoint = doc.AuthorizationEndpoint
		templateData.TokenEndpoint = doc.TokenEndpoint
		templateData.UserinfoEndpoint = doc.UserinfoEndpoint
		templateData.JWKSURI = doc.JWKSURI
		templateData.EndSessionEndpoint = doc.EndSessionEndpoint
	}
	applicationSecretName, envoySecretName, err := r.reconcileSecrets(ctx, &app, templateData)
	if err != nil {
		return r.failRequeue(ctx, &app, req, "SecretSyncFailed", err.Error())
	}

	// Reconcile SecurityPolicies (one per targetRef); only when targetRefs are set.
	var secPolicyRefs []v1alpha1.SecurityPolicyRef
	desiredNames := make(map[string]bool)
	for _, tr := range app.Spec.TargetRefs {
		desiredNames[fmt.Sprintf("%s-%s", app.Name, tr.Name)] = true
	}
	// Delete orphaned SecurityPolicies from previous reconciles (including all
	// of them when targetRefs is now empty).
	for _, ref := range app.Status.SecurityPolicies {
		if !desiredNames[ref.Name] {
			stale := &egv1alpha1.SecurityPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: ref.Name, Namespace: app.Namespace},
			}
			if derr := r.Delete(ctx, stale); client.IgnoreNotFound(derr) != nil {
				log.Error(derr, "failed to delete orphaned SecurityPolicy", "name", ref.Name)
			}
		}
	}

	if len(app.Spec.TargetRefs) > 0 {
		params := SecurityPolicyParams{
			AuthentikHost:   provider.Spec.Host,
			ApplicationSlug: slug,
			ClientID:        clientID,
			SecretName:      envoySecretName,
		}
		for _, tr := range app.Spec.TargetRefs {
			desired := BuildSecurityPolicy(&app, tr, params)
			existing := &egv1alpha1.SecurityPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: desired.Name, Namespace: desired.Namespace},
			}
			_, cerr := controllerutil.CreateOrUpdate(ctx, r.Client, existing, func() error {
				existing.Spec = desired.Spec
				existing.OwnerReferences = desired.OwnerReferences
				return nil
			})
			if cerr != nil {
				appmetrics.ReconcileErrors.WithLabelValues(req.Name, req.Namespace, "securitypolicy_sync").Inc()
				return ctrl.Result{}, fmt.Errorf("syncing SecurityPolicy %s: %w", desired.Name, cerr)
			}
			secPolicyRefs = append(secPolicyRefs, v1alpha1.SecurityPolicyRef{
				Name:        desired.Name,
				TargetRoute: tr.Name,
			})
		}
	}

	// Update status + requeue.
	app.Status.Authentik = &v1alpha1.AuthentikStatus{
		ProviderID:       oauthProvider.PK,
		ClientID:         clientID,
		ApplicationSlug:  slug,
		ApplicationID:    appObj.PK,
		PolicyBindingIDs: bindingIDs,
		BoundGroups:      groupNames(&app),
		CreatedGroups:    mergeCreated(app.Status.Authentik, createdGroups),
	}
	app.Status.SecurityPolicies = secPolicyRefs
	app.Status.SecretName = applicationSecretName
	r.setCondition(&app, metav1.ConditionTrue, "Reconciled", "All resources created successfully")
	appmetrics.PolicyStatus.WithLabelValues(req.Name, req.Namespace).Set(1)

	if err := r.Status().Update(ctx, &app); err != nil {
		return ctrl.Result{}, err
	}

	log.Info("OIDCApplication reconciled", "slug", slug)
	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

func (r *OIDCApplicationReconciler) cleanup(ctx context.Context, app *v1alpha1.OIDCApplication) error {
	if app.Status.Authentik == nil {
		return nil
	}

	// Get AuthentikProvider for API access. If we can't reach it, return an error
	// so the finalizer is retained and cleanup retries — silently succeeding here
	// would drop the finalizer and permanently orphan the Authentik provider,
	// application, bindings, and created groups.
	var provider v1alpha1.AuthentikProvider
	if err := r.Get(ctx, types.NamespacedName{Name: app.Spec.ProviderRef.Name}, &provider); err != nil {
		return fmt.Errorf("reading AuthentikProvider %q for cleanup: %w", app.Spec.ProviderRef.Name, err)
	}

	var secret corev1.Secret
	secretRef := types.NamespacedName{
		Name:      provider.Spec.APITokenSecretRef.Name,
		Namespace: provider.Spec.APITokenSecretRef.Namespace,
	}
	if err := r.Get(ctx, secretRef, &secret); err != nil {
		return fmt.Errorf("reading API token secret for cleanup: %w", err)
	}
	token := string(secret.Data[provider.Spec.APITokenSecretRef.Key])
	apiClient := authentik.NewClient(provider.Spec.Host, token)

	// Delete policy bindings.
	for _, bindingID := range app.Status.Authentik.PolicyBindingIDs {
		if err := apiClient.DeletePolicyBinding(ctx, bindingID); err != nil && !isNotFound(err) {
			return fmt.Errorf("deleting policy binding %s: %w", bindingID, err)
		}
	}

	// Delete application.
	if app.Status.Authentik.ApplicationSlug != "" {
		if err := apiClient.DeleteApplication(ctx, app.Status.Authentik.ApplicationSlug); err != nil && !isNotFound(err) {
			return fmt.Errorf("deleting application %s: %w", app.Status.Authentik.ApplicationSlug, err)
		}
	}

	// Delete provider.
	if app.Status.Authentik.ProviderID > 0 {
		if err := apiClient.DeleteProvider(ctx, app.Status.Authentik.ProviderID); err != nil && !isNotFound(err) {
			return fmt.Errorf("deleting provider %d: %w", app.Status.Authentik.ProviderID, err)
		}
	}

	// Delete groups the operator created that opted in to cleanup.
	cleanupNames := map[string]bool{}
	for _, g := range app.Spec.Groups {
		if g.Cleanup {
			cleanupNames[g.Name] = true
		}
	}
	for _, name := range app.Status.Authentik.CreatedGroups {
		if !cleanupNames[name] {
			continue
		}
		grp, err := apiClient.GetGroupByName(ctx, name)
		if err != nil {
			return fmt.Errorf("looking up group %q for cleanup: %w", name, err)
		}
		if grp == nil {
			continue // already gone
		}
		if err := apiClient.DeleteGroup(ctx, grp.PK); err != nil && !isNotFound(err) {
			return fmt.Errorf("deleting group %q: %w", name, err)
		}
	}

	return nil
}

// failRequeue records a not-ready condition, marks the app unhealthy, persists the
// status, and requeues after a fixed backoff. It centralizes the failure path
// shared by the pre-flight resolution steps.
func (r *OIDCApplicationReconciler) failRequeue(ctx context.Context, app *v1alpha1.OIDCApplication, req ctrl.Request, reason, msg string) (ctrl.Result, error) {
	r.setCondition(app, metav1.ConditionFalse, reason, msg)
	appmetrics.PolicyStatus.WithLabelValues(req.Name, req.Namespace).Set(0)
	if err := r.Status().Update(ctx, app); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

func (r *OIDCApplicationReconciler) setCondition(app *v1alpha1.OIDCApplication, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&app.Status.Conditions, metav1.Condition{
		Type:               ConditionReady,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})
}

func (r *OIDCApplicationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.OIDCApplication{}).
		Owns(&egv1alpha1.SecurityPolicy{}).
		Owns(&corev1.Secret{}).
		Watches(&v1alpha1.AuthentikProvider{}, handler.EnqueueRequestsFromMapFunc(r.mapProviderToApplications)).
		Watches(&gwapiv1.HTTPRoute{}, handler.EnqueueRequestsFromMapFunc(r.mapHTTPRouteToApplications)).
		Complete(r)
}

func (r *OIDCApplicationReconciler) mapProviderToApplications(ctx context.Context, obj client.Object) []reconcile.Request {
	var apps v1alpha1.OIDCApplicationList
	if err := r.List(ctx, &apps); err != nil {
		return nil
	}
	var requests []reconcile.Request
	for _, a := range apps.Items {
		if a.Spec.ProviderRef.Name == obj.GetName() {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: a.Name, Namespace: a.Namespace},
			})
		}
	}
	return requests
}

func (r *OIDCApplicationReconciler) mapHTTPRouteToApplications(ctx context.Context, obj client.Object) []reconcile.Request {
	var apps v1alpha1.OIDCApplicationList
	if err := r.List(ctx, &apps, client.InNamespace(obj.GetNamespace())); err != nil {
		return nil
	}
	var requests []reconcile.Request
	for _, a := range apps.Items {
		for _, ref := range a.Spec.TargetRefs {
			if ref.Name == obj.GetName() {
				requests = append(requests, reconcile.Request{
					NamespacedName: types.NamespacedName{Name: a.Name, Namespace: a.Namespace},
				})
				break
			}
		}
	}
	return requests
}

func groupNames(app *v1alpha1.OIDCApplication) []string {
	out := make([]string, 0, len(app.Spec.Groups))
	for _, g := range app.Spec.Groups {
		out = append(out, g.Name)
	}
	return out
}

// mergeCreated unions previously-created group names with those created this pass,
// so a group created in an earlier reconcile stays a cleanup candidate.
func mergeCreated(prev *v1alpha1.AuthentikStatus, justCreated []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(names []string) {
		for _, n := range names {
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	if prev != nil {
		add(prev.CreatedGroups)
	}
	add(justCreated)
	return out
}

func isNotFound(err error) bool {
	var apiErr *authentik.APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == 404
}
