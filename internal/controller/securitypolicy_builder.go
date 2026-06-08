package controller

import (
	"fmt"

	v1alpha1 "github.com/authentik-envoy-operator/authentik-envoy-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SecurityPolicyParams holds the dynamic values needed to build a SecurityPolicy.
type SecurityPolicyParams struct {
	AuthentikHost   string
	ApplicationSlug string
	ClientID        string
	SecretName      string
}

// SecurityPolicySpec is a simplified representation used by the builder.
type SecurityPolicySpec struct {
	TargetRef     TargetReference
	OIDC          OIDCSpec
	JWT           JWTSpec
	Authorization AuthorizationSpec
}

type TargetReference struct {
	Group string
	Kind  string
	Name  string
}

type OIDCSpec struct {
	Issuer             string
	ClientID           string
	ClientSecretName   string
	ForwardAccessToken bool
	Scopes             []string
	CookieNames        CookieNames
}

type CookieNames struct {
	AccessToken string
	IDToken     string
}

type JWTSpec struct {
	ProviderName string
	Issuer       string
	Audiences    []string
	JWKSURI      string
	CookieName   string
}

type AuthorizationSpec struct {
	AllowedGroups []string
	JWTProvider   string
}

// SecurityPolicyOutput is the output of the builder.
type SecurityPolicyOutput struct {
	metav1.ObjectMeta
	Spec SecurityPolicySpec
}

// BuildSecurityPolicy constructs the SecurityPolicy output for a single targetRef.
func BuildSecurityPolicy(policy *v1alpha1.OIDCPolicy, target v1alpha1.TargetRef, params SecurityPolicyParams) SecurityPolicyOutput {
	cookiePrefix := policy.Name
	if policy.Spec.OIDC.CookieConfig != nil && policy.Spec.OIDC.CookieConfig.NamePrefix != "" {
		cookiePrefix = policy.Spec.OIDC.CookieConfig.NamePrefix
	}

	issuer := fmt.Sprintf("%s/application/o/%s/", params.AuthentikHost, params.ApplicationSlug)
	jwksURI := fmt.Sprintf("%s/application/o/%s/jwks/", params.AuthentikHost, params.ApplicationSlug)

	return SecurityPolicyOutput{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", policy.Name, target.Name),
			Namespace: policy.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         v1alpha1.GroupVersion.String(),
					Kind:               "OIDCPolicy",
					Name:               policy.Name,
					UID:                policy.UID,
					Controller:         boolPtr(true),
					BlockOwnerDeletion: boolPtr(true),
				},
			},
		},
		Spec: SecurityPolicySpec{
			TargetRef: TargetReference{
				Group: "gateway.networking.k8s.io",
				Kind:  "HTTPRoute",
				Name:  target.Name,
			},
			OIDC: OIDCSpec{
				Issuer:             issuer,
				ClientID:           params.ClientID,
				ClientSecretName:   params.SecretName,
				ForwardAccessToken: policy.Spec.OIDC.ForwardAccessToken,
				Scopes:             policy.Spec.OIDC.Scopes,
				CookieNames: CookieNames{
					AccessToken: fmt.Sprintf("%s-accessToken", cookiePrefix),
					IDToken:     fmt.Sprintf("%s-idToken", cookiePrefix),
				},
			},
			JWT: JWTSpec{
				ProviderName: "authentik",
				Issuer:       issuer,
				Audiences:    []string{params.ClientID},
				JWKSURI:      jwksURI,
				CookieName:   fmt.Sprintf("%s-accessToken", cookiePrefix),
			},
			Authorization: AuthorizationSpec{
				AllowedGroups: policy.Spec.OIDC.AllowedGroups,
				JWTProvider:   "authentik",
			},
		},
	}
}

func boolPtr(b bool) *bool {
	return &b
}
