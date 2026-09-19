package controller

import (
	"fmt"
	"strings"

	egv1alpha1 "github.com/envoyproxy/gateway/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	v1alpha1 "github.com/swagner-de/authentik-envoy-operator/api/v1alpha1"
)

// SecurityPolicyParams holds the dynamic values needed to build a SecurityPolicy.
type SecurityPolicyParams struct {
	AuthentikHost   string
	ApplicationSlug string
	ClientID        string
	SecretName      string
}

// BuildSecurityPolicy constructs a typed Envoy Gateway SecurityPolicy for a single targetRef.
func BuildSecurityPolicy(app *v1alpha1.OIDCApplication, target v1alpha1.TargetRef, params SecurityPolicyParams) *egv1alpha1.SecurityPolicy {
	cookiePrefix := app.CookiePrefix()

	host := strings.TrimRight(params.AuthentikHost, "/")
	issuer := fmt.Sprintf("%s/application/o/%s/", host, params.ApplicationSlug)
	jwksURI := fmt.Sprintf("%s/application/o/%s/jwks/", host, params.ApplicationSlug)

	accessTokenCookie := fmt.Sprintf("%s-accessToken", cookiePrefix)
	idTokenCookie := fmt.Sprintf("%s-idToken", cookiePrefix)

	forwardAccessToken := app.ForwardAccessTokenEnabled()

	scopes := app.EffectiveScopes()

	group := gwapiv1.Group("gateway.networking.k8s.io")
	kind := gwapiv1.Kind("HTTPRoute")
	ns := gwapiv1.Namespace(app.Namespace)
	secretGroup := gwapiv1.Group("")
	secretKind := gwapiv1.Kind("Secret")

	denyAction := egv1alpha1.AuthorizationAction("Deny")
	allowAction := egv1alpha1.AuthorizationActionAllow
	claimValueType := egv1alpha1.JWTClaimValueTypeStringArray
	cacheDuration := gwapiv1.Duration("300s")
	allowRuleName := "allow-groups"

	sp := &egv1alpha1.SecurityPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "gateway.envoyproxy.io/v1alpha1",
			Kind:       "SecurityPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", app.Name, target.Name),
			Namespace: app.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         v1alpha1.GroupVersion.String(),
					Kind:               "OIDCApplication",
					Name:               app.Name,
					UID:                app.UID,
					Controller:         boolPtr(true),
					BlockOwnerDeletion: boolPtr(true),
				},
			},
		},
		Spec: egv1alpha1.SecurityPolicySpec{
			PolicyTargetReferences: egv1alpha1.PolicyTargetReferences{
				TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{
					{
						LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{
							Group: group,
							Kind:  kind,
							Name:  gwapiv1.ObjectName(target.Name),
						},
					},
				},
			},
			OIDC: &egv1alpha1.OIDC{
				Provider: egv1alpha1.OIDCProvider{
					Issuer: issuer,
				},
				ClientID: &params.ClientID,
				ClientSecret: gwapiv1.SecretObjectReference{
					Group:     &secretGroup,
					Kind:      &secretKind,
					Name:      gwapiv1.ObjectName(params.SecretName),
					Namespace: &ns,
				},
				CookieNames: &egv1alpha1.OIDCCookieNames{
					AccessToken: &accessTokenCookie,
					IDToken:     &idTokenCookie,
				},
				ForwardAccessToken: &forwardAccessToken,
				Scopes:             scopes,
			},
			JWT: &egv1alpha1.JWT{
				Providers: []egv1alpha1.JWTProvider{
					{
						Name:      "authentik",
						Issuer:    issuer,
						Audiences: []string{params.ClientID},
						RemoteJWKS: &egv1alpha1.RemoteJWKS{
							URI:           jwksURI,
							CacheDuration: &cacheDuration,
						},
						ExtractFrom: &egv1alpha1.JWTExtractor{
							Cookies: []string{accessTokenCookie},
						},
					},
				},
			},
			Authorization: &egv1alpha1.Authorization{
				DefaultAction: &denyAction,
				Rules: []egv1alpha1.AuthorizationRule{
					{
						Name:   &allowRuleName,
						Action: allowAction,
						Principal: egv1alpha1.Principal{
							JWT: &egv1alpha1.JWTPrincipal{
								Provider: "authentik",
								Claims: []egv1alpha1.JWTClaim{
									{
										Name:      "groups",
										ValueType: &claimValueType,
										Values:    groupNames(app),
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Honor optional cookie hardening/scoping from the CR.
	if cc := app.Spec.CookieConfig; cc != nil {
		if cc.SameSite != "" {
			sameSite := cc.SameSite
			sp.Spec.OIDC.CookieConfig = &egv1alpha1.OIDCCookieConfig{SameSite: &sameSite}
		}
		if cc.Domain != "" {
			domain := cc.Domain
			sp.Spec.OIDC.CookieDomain = &domain
		}
	}

	return sp
}

func boolPtr(b bool) *bool {
	return &b
}
