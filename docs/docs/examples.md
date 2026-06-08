# Examples

## Protecting Grafana with OIDC

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
kind: OIDCPolicy
metadata:
  name: grafana
  namespace: monitoring
spec:
  providerRef:
    name: main
  targetRefs:
    - name: grafana
  oidc:
    allowedGroups:
      - admins
      - developers
    scopes:
      - openid
      - profile
      - email
    signingKey: "authentik Self-signed Certificate"
    propertyMappings:
      - "authentik default OAuth Mapping: OpenID 'openid'"
      - "authentik default OAuth Mapping: OpenID 'profile'"
      - "authentik default OAuth Mapping: OpenID 'email'"
```

## Multiple Routes, One Policy

Protect both a UI and API route with the same OIDC configuration:

```yaml
apiVersion: authentik-envoy-operator.io/v1alpha1
kind: OIDCPolicy
metadata:
  name: my-app
  namespace: default
spec:
  providerRef:
    name: main
  targetRefs:
    - name: my-app-ui
    - name: my-app-api
  oidc:
    allowedGroups:
      - users
    scopes:
      - openid
      - profile
    signingKey: "authentik Self-signed Certificate"
    propertyMappings:
      - "authentik default OAuth Mapping: OpenID 'openid'"
      - "authentik default OAuth Mapping: OpenID 'profile'"
```

This creates two `SecurityPolicy` resources (`my-app-my-app-ui` and `my-app-my-app-api`), each targeting their respective HTTPRoute but sharing the same Authentik application and client credentials.

## Custom Cookie Configuration

```yaml
apiVersion: authentik-envoy-operator.io/v1alpha1
kind: OIDCPolicy
metadata:
  name: my-app
  namespace: default
spec:
  providerRef:
    name: main
  targetRefs:
    - name: my-app-route
  oidc:
    allowedGroups:
      - admins
    scopes:
      - openid
    signingKey: "authentik Self-signed Certificate"
    propertyMappings:
      - "authentik default OAuth Mapping: OpenID 'openid'"
    cookieConfig:
      namePrefix: "_myapp"
```

## Forwarding Access Token to Backend

```yaml
apiVersion: authentik-envoy-operator.io/v1alpha1
kind: OIDCPolicy
metadata:
  name: my-app
  namespace: default
spec:
  providerRef:
    name: main
  targetRefs:
    - name: my-app-route
  oidc:
    allowedGroups:
      - admins
    scopes:
      - openid
      - profile
    signingKey: "authentik Self-signed Certificate"
    propertyMappings:
      - "authentik default OAuth Mapping: OpenID 'openid'"
      - "authentik default OAuth Mapping: OpenID 'profile'"
    forwardAccessToken: true
```
