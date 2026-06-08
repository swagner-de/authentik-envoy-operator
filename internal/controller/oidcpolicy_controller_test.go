package controller

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/authentik-envoy-operator/authentik-envoy-operator/api/v1alpha1"
)

func TestOIDCPolicyReconcileNotFound(t *testing.T) {
	scheme := newTestScheme()

	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	reconciler := &OIDCPolicyReconciler{Client: k8s, Scheme: scheme}

	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "nonexistent", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile should not error for not-found resource: %v", err)
	}
}

func TestOIDCPolicyReconcileProviderNotFound(t *testing.T) {
	scheme := newTestScheme()

	policy := &v1alpha1.OIDCPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Finalizers: []string{finalizerName},
		},
		Spec: v1alpha1.OIDCPolicySpec{
			ProviderRef: v1alpha1.ProviderRef{Name: "nonexistent-provider"},
			TargetRefs:  []v1alpha1.TargetRef{{Name: "route"}},
			OIDC: v1alpha1.OIDCConfig{
				AllowedGroups: []string{"admins"},
				SigningKey:     "key",
			},
		},
	}

	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy).
		WithStatusSubresource(policy).
		Build()

	reconciler := &OIDCPolicyReconciler{Client: k8s, Scheme: scheme}

	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-policy", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile should not return error (requeues): %v", err)
	}
	if result.RequeueAfter == 0 {
		t.Error("expected requeue when provider not found")
	}

	// Verify condition reflects the error
	var updated v1alpha1.OIDCPolicy
	if err := k8s.Get(context.Background(), types.NamespacedName{Name: "test-policy", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("failed to get policy: %v", err)
	}
	if len(updated.Status.Conditions) == 0 {
		t.Fatal("expected status conditions")
	}
	if updated.Status.Conditions[0].Reason != "ProviderNotFound" {
		t.Errorf("expected reason ProviderNotFound, got %s", updated.Status.Conditions[0].Reason)
	}
}

func TestOIDCPolicyReconcileAddsFinalizer(t *testing.T) {
	scheme := newTestScheme()

	policy := &v1alpha1.OIDCPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: v1alpha1.OIDCPolicySpec{
			ProviderRef: v1alpha1.ProviderRef{Name: "main"},
			TargetRefs:  []v1alpha1.TargetRef{{Name: "route"}},
			OIDC: v1alpha1.OIDCConfig{
				AllowedGroups: []string{"admins"},
				SigningKey:     "key",
			},
		},
	}

	k8s := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy).
		WithStatusSubresource(policy).
		Build()

	reconciler := &OIDCPolicyReconciler{Client: k8s, Scheme: scheme}

	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-policy", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// Verify finalizer was added
	var updated v1alpha1.OIDCPolicy
	if err := k8s.Get(context.Background(), types.NamespacedName{Name: "test-policy", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("failed to get policy: %v", err)
	}
	found := false
	for _, f := range updated.Finalizers {
		if f == finalizerName {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finalizer to be added")
	}
}
