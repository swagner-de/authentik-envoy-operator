package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TargetRef identifies an HTTPRoute by name (same namespace as OIDCPolicy).
type TargetRef struct {
	// Name of the HTTPRoute.
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

// ProviderRef references a cluster-scoped AuthentikProvider.
type ProviderRef struct {
	// Name of the AuthentikProvider resource.
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

// CookieConfig defines cookie settings for the OIDC session.
type CookieConfig struct {
	// NamePrefix is the prefix for cookie names. Defaults to the OIDCPolicy name.
	NamePrefix string `json:"namePrefix,omitempty"`

	// Domain sets the cookie domain. Empty means the browser uses the request domain.
	Domain string `json:"domain,omitempty"`

	// SameSite attribute for cookies.
	// +kubebuilder:default="Lax"
	// +kubebuilder:validation:Enum=Lax;Strict;None
	SameSite string `json:"sameSite,omitempty"`
}

// OIDCConfig defines the OIDC authentication settings.
type OIDCConfig struct {
	// AllowedGroups are the Authentik groups permitted to access the protected routes.
	// At least one group is required.
	// +kubebuilder:validation:MinItems=1
	AllowedGroups []string `json:"allowedGroups"`

	// Scopes to request from the OIDC provider.
	// +kubebuilder:default={"openid","profile"}
	Scopes []string `json:"scopes,omitempty"`

	// ForwardAccessToken passes the access token to upstream services.
	// +kubebuilder:default=true
	ForwardAccessToken bool `json:"forwardAccessToken,omitempty"`

	// RedirectURL overrides the auto-derived redirect URL.
	// If empty, it is derived from the first HTTPRoute's hostname.
	RedirectURL string `json:"redirectURL,omitempty"`

	// CookieConfig defines cookie behavior.
	CookieConfig *CookieConfig `json:"cookieConfig,omitempty"`
}

// OIDCPolicySpec defines the desired OIDC protection for HTTPRoutes.
type OIDCPolicySpec struct {
	// ProviderRef references a cluster-scoped AuthentikProvider.
	// +kubebuilder:validation:Required
	ProviderRef ProviderRef `json:"providerRef"`

	// TargetRefs identifies the HTTPRoutes to protect (same namespace).
	// +kubebuilder:validation:MinItems=1
	TargetRefs []TargetRef `json:"targetRefs"`

	// OIDC defines the authentication configuration.
	// +kubebuilder:validation:Required
	OIDC OIDCConfig `json:"oidc"`
}

// AuthentikStatus tracks created Authentik resources.
type AuthentikStatus struct {
	ProviderID       int      `json:"providerID,omitempty"`
	ClientID         string   `json:"clientID,omitempty"`
	ApplicationSlug  string   `json:"applicationSlug,omitempty"`
	ApplicationID    string   `json:"applicationID,omitempty"`
	PolicyBindingIDs []string `json:"policyBindingIDs,omitempty"`
}

// SecurityPolicyRef tracks a created SecurityPolicy.
type SecurityPolicyRef struct {
	Name        string `json:"name"`
	TargetRoute string `json:"targetRoute"`
}

// OIDCPolicyStatus defines the observed state.
type OIDCPolicyStatus struct {
	// Conditions represent the latest available observations.
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Authentik tracks created Authentik resources.
	Authentik *AuthentikStatus `json:"authentik,omitempty"`

	// SecurityPolicies lists the created SecurityPolicy resources.
	SecurityPolicies []SecurityPolicyRef `json:"securityPolicies,omitempty"`

	// SecretName is the name of the Secret containing the OIDC client credentials.
	SecretName string `json:"secretName,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Provider",type=string,JSONPath=`.spec.providerRef.name`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// OIDCPolicy defines OIDC protection for one or more HTTPRoutes.
type OIDCPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OIDCPolicySpec   `json:"spec,omitempty"`
	Status OIDCPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OIDCPolicyList contains a list of OIDCPolicy.
type OIDCPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OIDCPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OIDCPolicy{}, &OIDCPolicyList{})
}
