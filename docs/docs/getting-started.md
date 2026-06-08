# Getting Started

## Prerequisites

- Kubernetes cluster with [Envoy Gateway](https://gateway.envoyproxy.io/) installed
- [Authentik](https://goauthentik.io/) instance with API access
- Helm 3.x

## Installation

### Via Helm

```bash
helm install authentik-envoy-operator ./charts/authentik-envoy-operator \
  --namespace authentik-envoy-operator \
  --create-namespace \
  --set image.repository=registry.mannheim.sebwagner.de/authentik-envoy-operator \
  --set image.tag=latest \
  --set webhook.enabled=false
```

### Authentik API Token

Create an API token in Authentik with the following permissions:

- Read/Write access to **Providers** (OAuth2)
- Read/Write access to **Applications**
- Read/Write access to **Policy Bindings**
- Read access to **Groups**
- Read access to **Flows**
- Read access to **Certificate Key Pairs**
- Read access to **Property Mappings**

Store the token in a Kubernetes Secret:

```bash
kubectl create secret generic authentik-api-token \
  --namespace authentik \
  --from-literal=token=YOUR_API_TOKEN
```

## Configuration

### 1. Create an AuthentikProvider

```yaml
apiVersion: authentik-envoy-operator.io/v1alpha1
kind: AuthentikProvider
metadata:
  name: main
spec:
  host: "https://authentik.example.com"
  apiTokenSecretRef:
    name: authentik-api-token
    namespace: authentik
    key: token
  authorizationFlowSlug: "default-provider-authorization-implicit-consent"
  invalidationFlowSlug: "default-provider-invalidation-flow"
```

### 2. Create an OIDCPolicy

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
      - email
    signingKey: "authentik Self-signed Certificate"
    propertyMappings:
      - "authentik default OAuth Mapping: OpenID 'openid'"
      - "authentik default OAuth Mapping: OpenID 'profile'"
      - "authentik default OAuth Mapping: OpenID 'email'"
```

### 3. Verify

```bash
# Check AuthentikProvider connectivity
kubectl get authentikproviders

# Check OIDCPolicy status
kubectl get oidcpolicies -A

# Check created SecurityPolicies
kubectl get securitypolicies -A
```

## What Happens Next

The operator will:

1. Resolve the signing key and property mappings in Authentik
2. Create an OAuth2 Provider named `<namespace>-<name>`
3. Create an Application with the same slug
4. Bind the allowed groups to the application
5. Extract hostnames from the referenced HTTPRoute(s) to build redirect URIs
6. Sync the generated client secret to `<name>-client-secret` in the same namespace
7. Create a `SecurityPolicy` per target HTTPRoute configuring Envoy Gateway OIDC filter
