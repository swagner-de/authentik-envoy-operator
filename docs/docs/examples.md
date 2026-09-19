# Examples

## Protecting Grafana with OIDC (Envoy mode)

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: grafana
  namespace: monitoring
spec:
  parentRefs:
    - name: envoy-gateway
      namespace: envoy-gateway-system
  hostnames:
    - grafana.example.com
  rules:
    - backendRefs:
        - name: grafana
          port: 3000
---
apiVersion: authentik-envoy-operator.io/v1alpha1
kind: OIDCApplication
metadata:
  name: grafana
  namespace: monitoring
spec:
  providerRef:
    name: main
  displayName: "Grafana"
  signingKey: "authentik Self-signed Certificate"
  scopes:
    - openid
    - profile
    - email
  propertyMappings:
    - "authentik default OAuth Mapping: OpenID 'openid'"
    - "authentik default OAuth Mapping: OpenID 'profile'"
    - "authentik default OAuth Mapping: OpenID 'email'"
  groups:
    - name: admins
      create: false
    - name: developers
      create: false
  targetRefs:
    - name: grafana
```

`targetRefs` independently creates the fixed `grafana-envoy-oidc` Secret with
exactly `client-secret`. The generated `SecurityPolicy` references that Secret;
`spec.secretName` cannot rename it.

## Standalone (native OIDC, no Envoy)

For an app that performs the OIDC flow itself. A nonempty `secretTemplate` opts
in to an application Secret. This Mealie example emits environment-style keys:

```yaml
apiVersion: authentik-envoy-operator.io/v1alpha1
kind: OIDCApplication
metadata:
  name: mealie
  namespace: mealie
spec:
  providerRef:
    name: main
  displayName: "Mealie"
  signingKey: "authentik Self-signed Certificate"
  scopes: [openid, profile, email]
  propertyMappings:
    - "authentik default OAuth Mapping: OpenID 'openid'"
    - "authentik default OAuth Mapping: OpenID 'profile'"
    - "authentik default OAuth Mapping: OpenID 'email'"
  groups:
    - name: mealie-users
      create: true       # create the group in Authentik if it doesn't exist
      cleanup: true       # delete it again when this OIDCApplication is deleted
  redirectURIs:
    - "https://mealie.example.com/login"
  secretTemplate:
    OIDC_AUTH_ENABLED: "true"
    OIDC_CLIENT_ID: "{{ .ClientID }}"
    OIDC_CLIENT_SECRET: "{{ .ClientSecret }}"
    OIDC_CONFIGURATION_URL: "{{ .DiscoveryURL }}"
    OIDC_SIGNUP_ENABLED: "true"
```

The resulting `mealie-oidc` Secret contains exactly those five keys. Set
`spec.secretName` to choose a different application Secret name.

## JSON-Valued Application Secret (Paperless)

Use `quote` when inserting values into JSON so quotes, backslashes, and control
characters are escaped correctly:

```yaml
spec:
  # ...
  secretTemplate:
    PAPERLESS_SOCIALACCOUNT_PROVIDERS: >-
      [{"provider":"openid_connect","name":"Authentik","settings":{"server_url":{{ .DiscoveryURL | quote }},"client_id":{{ .ClientID | quote }},"secret":{{ .ClientSecret | quote }}}}]
```

Available context fields are `.ClientID`, `.ClientSecret`, `.Issuer`,
`.DiscoveryURL`, `.AuthorizationEndpoint`, `.TokenEndpoint`,
`.UserinfoEndpoint`, `.JWKSURI`, and `.EndSessionEndpoint`. The four
operator-provided custom functions are `quote`, `toJson`, `trimPrefix`, and
`trimSuffix`; normal Go `text/template` actions and built-ins remain available,
but only these four custom functions are guaranteed and documented. They support
pipeline use, for example
`{{ .Issuer | trimPrefix "https://" | trimSuffix "/" }}`.

If any template is invalid, the `Ready` condition becomes `False` with reason
`SecretSyncFailed`; the last valid Secret is left unchanged, and template
context values are omitted from logs and the condition. If Authentik omits an
existing client secret, previously rendered application Secret entries that
depend on `.ClientSecret` are retained by key instead of being replaced with an
empty value. The Envoy Secret separately retains only its own existing
`client-secret`; application Secret data never seeds it.

## Multiple Routes, One Application

```yaml
apiVersion: authentik-envoy-operator.io/v1alpha1
kind: OIDCApplication
metadata:
  name: my-app
  namespace: default
spec:
  providerRef:
    name: main
  signingKey: "authentik Self-signed Certificate"
  scopes: [openid, profile]
  propertyMappings:
    - "authentik default OAuth Mapping: OpenID 'openid'"
    - "authentik default OAuth Mapping: OpenID 'profile'"
  groups:
    - name: users
      create: false
  targetRefs:
    - name: my-app-ui
    - name: my-app-api
```

This creates two `SecurityPolicy` resources (`my-app-my-app-ui` and
`my-app-my-app-api`), each targeting its HTTPRoute but sharing the same Authentik
application and client credentials.

## Custom Cookie Configuration

```yaml
spec:
  # ...
  cookieConfig:
    namePrefix: "_myapp"
    sameSite: Lax
```

## Forwarding the Access Token to the Backend

```yaml
spec:
  # ...
  forwardAccessToken: true
  targetRefs:
    - name: my-app-route
```

!!! note
    Authorization matches the token's `groups` claim, so include a
    `propertyMappings` entry that emits `groups`, and use an asymmetric **RSA or
    EC** `signingKey` so tokens are verifiable via JWKS.
