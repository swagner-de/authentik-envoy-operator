package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha1 "github.com/authentik-envoy-operator/authentik-envoy-operator/api/v1alpha1"
	"github.com/authentik-envoy-operator/authentik-envoy-operator/internal/authentik"
	appmetrics "github.com/authentik-envoy-operator/authentik-envoy-operator/internal/metrics"
)

const (
	ConditionConnected = "Connected"
)

// AuthentikProviderReconciler reconciles AuthentikProvider resources.
type AuthentikProviderReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=authentik-envoy-operator.io,resources=authentikproviders,verbs=get;list;watch
// +kubebuilder:rbac:groups=authentik-envoy-operator.io,resources=authentikproviders/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

func (r *AuthentikProviderReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	var provider v1alpha1.AuthentikProvider
	if err := r.Get(ctx, req.NamespacedName, &provider); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Read API token from secret
	var secret corev1.Secret
	secretRef := types.NamespacedName{
		Name:      provider.Spec.APITokenSecretRef.Name,
		Namespace: provider.Spec.APITokenSecretRef.Namespace,
	}
	if err := r.Get(ctx, secretRef, &secret); err != nil {
		log.Error(err, "failed to read API token secret")
		r.setCondition(&provider, metav1.ConditionFalse, "SecretNotFound", err.Error())
		appmetrics.ProviderConnected.WithLabelValues(provider.Name).Set(0)
		if err := r.Status().Update(ctx, &provider); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 1 * time.Minute}, nil
	}

	token := string(secret.Data[provider.Spec.APITokenSecretRef.Key])
	if token == "" {
		r.setCondition(&provider, metav1.ConditionFalse, "TokenEmpty", "API token key is empty in secret")
		appmetrics.ProviderConnected.WithLabelValues(provider.Name).Set(0)
		if err := r.Status().Update(ctx, &provider); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 1 * time.Minute}, nil
	}

	// Verify connectivity by resolving flows
	apiClient := authentik.NewClient(provider.Spec.Host, token)

	authFlow, err := apiClient.GetFlowBySlug(ctx, provider.Spec.AuthorizationFlowSlug)
	if err != nil {
		log.Error(err, "failed to resolve authorization flow")
		r.setCondition(&provider, metav1.ConditionFalse, "FlowResolutionFailed", fmt.Sprintf("authorization flow: %v", err))
		appmetrics.ProviderConnected.WithLabelValues(provider.Name).Set(0)
		if err := r.Status().Update(ctx, &provider); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 1 * time.Minute}, nil
	}
	if authFlow == nil {
		r.setCondition(&provider, metav1.ConditionFalse, "FlowNotFound", fmt.Sprintf("authorization flow %q not found", provider.Spec.AuthorizationFlowSlug))
		appmetrics.ProviderConnected.WithLabelValues(provider.Name).Set(0)
		if err := r.Status().Update(ctx, &provider); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 1 * time.Minute}, nil
	}

	invalFlow, err := apiClient.GetFlowBySlug(ctx, provider.Spec.InvalidationFlowSlug)
	if err != nil {
		log.Error(err, "failed to resolve invalidation flow")
		r.setCondition(&provider, metav1.ConditionFalse, "FlowResolutionFailed", fmt.Sprintf("invalidation flow: %v", err))
		appmetrics.ProviderConnected.WithLabelValues(provider.Name).Set(0)
		if err := r.Status().Update(ctx, &provider); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 1 * time.Minute}, nil
	}
	if invalFlow == nil {
		r.setCondition(&provider, metav1.ConditionFalse, "FlowNotFound", fmt.Sprintf("invalidation flow %q not found", provider.Spec.InvalidationFlowSlug))
		appmetrics.ProviderConnected.WithLabelValues(provider.Name).Set(0)
		if err := r.Status().Update(ctx, &provider); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 1 * time.Minute}, nil
	}

	// Success — update status
	provider.Status.AuthorizationFlowUID = authFlow.PK
	provider.Status.InvalidationFlowUID = invalFlow.PK
	r.setCondition(&provider, metav1.ConditionTrue, "APIReachable", "Successfully connected to Authentik API")
	appmetrics.ProviderConnected.WithLabelValues(provider.Name).Set(1)

	if err := r.Status().Update(ctx, &provider); err != nil {
		return ctrl.Result{}, err
	}

	log.Info("AuthentikProvider reconciled", "host", provider.Spec.Host)
	return ctrl.Result{RequeueAfter: 10 * time.Minute}, nil
}

func (r *AuthentikProviderReconciler) setCondition(provider *v1alpha1.AuthentikProvider, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&provider.Status.Conditions, metav1.Condition{
		Type:               ConditionConnected,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})
}

func (r *AuthentikProviderReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.AuthentikProvider{}).
		Complete(r)
}
