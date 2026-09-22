package v1alpha1

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ProviderRef references a cluster-scoped AuthentikProvider.
type ProviderRef struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// TargetRef identifies a Gateway API route to protect with a SecurityPolicy.
type TargetRef struct {
	// +kubebuilder:default="gateway.networking.k8s.io"
	Group string `json:"group,omitempty"`
	// +kubebuilder:default="HTTPRoute"
	Kind string `json:"kind,omitempty"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// GroupRef is a group to bind to the application. create=false requires it to
// already exist; create=true creates it if missing. cleanup=true deletes it on
// OIDCApplication deletion, but only if the operator created it.
type GroupRef struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +kubebuilder:default=false
	Create bool `json:"create,omitempty"`
	// +kubebuilder:default=false
	Cleanup bool `json:"cleanup,omitempty"`
}

// CookieConfig defines cookie settings for the Envoy OIDC session.
type CookieConfig struct {
	NamePrefix string `json:"namePrefix,omitempty"`
	Domain     string `json:"domain,omitempty"`
	// +kubebuilder:default="Lax"
	// +kubebuilder:validation:Enum=Lax;Strict;None
	SameSite string `json:"sameSite,omitempty"`
}

// AppMeta holds Authentik application launcher metadata (passthrough).
type AppMeta struct {
	LaunchURL    string `json:"launchURL,omitempty"`
	Description  string `json:"description,omitempty"`
	Publisher    string `json:"publisher,omitempty"`
	Icon         string `json:"icon,omitempty"`
	OpenInNewTab bool   `json:"openInNewTab,omitempty"`
	Group        string `json:"group,omitempty"`
}

// OIDCApplicationSpec defines an Authentik application, optionally fronted by Envoy.
type OIDCApplicationSpec struct {
	// +kubebuilder:validation:Required
	ProviderRef ProviderRef `json:"providerRef"`

	// DisplayName is the Authentik application name. Defaults to metadata.name.
	DisplayName string `json:"displayName,omitempty"`
	// Slug is the stable identifier (Authentik slug, client_id, provider name).
	// Defaults to "<namespace>-<name>". Immutable.
	// +kubebuilder:validation:MaxLength=50
	// +kubebuilder:validation:Pattern=`^[-a-zA-Z0-9_]+$`
	Slug string `json:"slug,omitempty"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	SigningKey string `json:"signingKey"`

	PropertyMappings []string `json:"propertyMappings,omitempty"`
	// +kubebuilder:default={"openid","profile"}
	Scopes []string `json:"scopes,omitempty"`
	// +kubebuilder:default=true
	ForwardAccessToken *bool `json:"forwardAccessToken,omitempty"`

	// Provider tuning (optional passthrough).
	SubMode string `json:"subMode,omitempty"`
	// +kubebuilder:default=true
	IncludeClaimsInIDToken *bool  `json:"includeClaimsInIDToken,omitempty"`
	AccessTokenValidity    string `json:"accessTokenValidity,omitempty"`
	RefreshTokenValidity   string `json:"refreshTokenValidity,omitempty"`
	AccessCodeValidity     string `json:"accessCodeValidity,omitempty"`

	// +kubebuilder:validation:MinItems=1
	Groups []GroupRef `json:"groups"`

	RedirectURIs []string `json:"redirectURIs,omitempty"`

	CookieConfig *CookieConfig `json:"cookieConfig,omitempty"`
	AppMeta      *AppMeta      `json:"appMeta,omitempty"`

	// TargetRefs are Gateway API routes to protect. Empty ⇒ standalone (no SecurityPolicy).
	TargetRefs []TargetRef `json:"targetRefs,omitempty"`

	// SecretName overrides the application Secret name. It is used only when
	// SecretTemplate contains entries and defaults to "<metadata.name>-oidc".
	SecretName string `json:"secretName,omitempty"`

	// SecretTemplate maps Secret data keys to Go templates rendered from the OIDC
	// provider credentials and discovery document.
	// +kubebuilder:validation:XValidation:rule="self.all(k, k.size() <= 253 && k.matches('^[-._a-zA-Z0-9]+$'))",message="keys must be valid Kubernetes Secret data keys"
	SecretTemplate map[string]string `json:"secretTemplate,omitempty"`
}

// AuthentikStatus tracks created Authentik resources.
type AuthentikStatus struct {
	ProviderID       int      `json:"providerID,omitempty"`
	ClientID         string   `json:"clientID,omitempty"`
	ApplicationSlug  string   `json:"applicationSlug,omitempty"`
	ApplicationID    string   `json:"applicationID,omitempty"`
	PolicyBindingIDs []string `json:"policyBindingIDs,omitempty"`
	BoundGroups      []string `json:"boundGroups,omitempty"`
	// CreatedGroups are groups the operator created (candidates for cleanup).
	CreatedGroups []string `json:"createdGroups,omitempty"`
}

// SecurityPolicyRef tracks a created SecurityPolicy.
type SecurityPolicyRef struct {
	Name        string `json:"name"`
	TargetRoute string `json:"targetRoute"`
}

// OIDCApplicationStatus defines the observed state.
type OIDCApplicationStatus struct {
	Conditions       []metav1.Condition  `json:"conditions,omitempty"`
	Authentik        *AuthentikStatus    `json:"authentik,omitempty"`
	SecurityPolicies []SecurityPolicyRef `json:"securityPolicies,omitempty"`
	SecretName       string              `json:"secretName,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Provider",type=string,JSONPath=`.spec.providerRef.name`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// OIDCApplication provisions an Authentik OAuth2 application, optionally fronted by Envoy.
type OIDCApplication struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OIDCApplicationSpec   `json:"spec,omitempty"`
	Status OIDCApplicationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OIDCApplicationList contains a list of OIDCApplication.
type OIDCApplicationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OIDCApplication `json:"items"`
}

func (a *OIDCApplication) EffectiveSlug() string {
	if a.Spec.Slug != "" {
		return a.Spec.Slug
	}
	return fmt.Sprintf("%s-%s", a.Namespace, a.Name)
}

func (a *OIDCApplication) EffectiveDisplayName() string {
	if a.Spec.DisplayName != "" {
		return a.Spec.DisplayName
	}
	return a.Name
}

func (a *OIDCApplication) EffectiveSecretName() string {
	if a.Spec.SecretName != "" {
		return a.Spec.SecretName
	}
	return fmt.Sprintf("%s-oidc", a.Name)
}

func (a *OIDCApplication) EnvoySecretName() string {
	return fmt.Sprintf("%s-envoy-oidc", a.Name)
}

func (a *OIDCApplication) CookiePrefix() string {
	if a.Spec.CookieConfig != nil && a.Spec.CookieConfig.NamePrefix != "" {
		return a.Spec.CookieConfig.NamePrefix
	}
	return a.Name
}

func (a *OIDCApplication) EffectiveScopes() []string {
	if len(a.Spec.Scopes) > 0 {
		return a.Spec.Scopes
	}
	return []string{"openid", "profile"}
}

// ForwardAccessTokenEnabled reports whether the access token should be forwarded
// upstream. It defaults to true when unset (matching the CRD default).
func (a *OIDCApplication) ForwardAccessTokenEnabled() bool {
	if a.Spec.ForwardAccessToken != nil {
		return *a.Spec.ForwardAccessToken
	}
	return true
}
