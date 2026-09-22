package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SecretKeyReference holds a reference to a key within a Secret.
type SecretKeyReference struct {
	// Name of the Secret.
	Name string `json:"name"`
	// Namespace of the Secret.
	Namespace string `json:"namespace"`
	// Key within the Secret.
	Key string `json:"key"`
}

// AuthentikProviderSpec defines the connection to an Authentik instance.
type AuthentikProviderSpec struct {
	// Host is the base URL of the Authentik instance (e.g., "https://authentik.example.com").
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^https?://`
	Host string `json:"host"`

	// APITokenSecretRef references a Secret containing the Authentik API token.
	// +kubebuilder:validation:Required
	APITokenSecretRef SecretKeyReference `json:"apiTokenSecretRef"`

	// AuthorizationFlowSlug is the slug of the authorization flow to use.
	// +kubebuilder:default="default-provider-authorization-implicit-consent"
	AuthorizationFlowSlug string `json:"authorizationFlowSlug,omitempty"`

	// InvalidationFlowSlug is the slug of the invalidation flow to use.
	// +kubebuilder:default="default-provider-invalidation-flow"
	InvalidationFlowSlug string `json:"invalidationFlowSlug,omitempty"`
}

// AuthentikProviderStatus defines the observed state.
type AuthentikProviderStatus struct {
	// Conditions represent the latest available observations.
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// AuthorizationFlowUID is the resolved UUID of the authorization flow.
	AuthorizationFlowUID string `json:"authorizationFlowUID,omitempty"`

	// InvalidationFlowUID is the resolved UUID of the invalidation flow.
	InvalidationFlowUID string `json:"invalidationFlowUID,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Host",type=string,JSONPath=`.spec.host`
// +kubebuilder:printcolumn:name="Connected",type=string,JSONPath=`.status.conditions[?(@.type=="Connected")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// AuthentikProvider represents a connection to an Authentik identity provider instance.
type AuthentikProvider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AuthentikProviderSpec   `json:"spec,omitempty"`
	Status AuthentikProviderStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AuthentikProviderList contains a list of AuthentikProvider.
type AuthentikProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AuthentikProvider `json:"items"`
}
