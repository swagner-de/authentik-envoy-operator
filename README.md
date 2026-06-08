# Authentik Envoy Operator

A Kubernetes operator that automates OIDC authentication for services behind Envoy Gateway by managing Authentik OAuth2 providers and Envoy Gateway SecurityPolicy resources.

## Overview

This operator watches `OIDCPolicy` custom resources and:

1. Creates an OAuth2 provider and application in Authentik
2. Configures group-based access control via Authentik policy bindings
3. Syncs the generated client secret to a Kubernetes Secret
4. Creates an Envoy Gateway `SecurityPolicy` with OIDC, JWT validation, and group-based authorization

## Prerequisites

- Kubernetes 1.28+
- Envoy Gateway 1.0+
- Authentik instance with API token
- Gateway API CRDs installed

## Installation

### Helm

```bash
helm install authentik-envoy-operator ./charts/authentik-envoy-operator \
  --namespace authentik-system --create-namespace
```

## Custom Resources

### AuthentikProvider (cluster-scoped)

Defines the connection to an Authentik instance:

```yaml
apiVersion: authentik-envoy-operator.io/v1alpha1
kind: AuthentikProvider
metadata:
  name: main
spec:
  host: "https://authentik.example.com"
  apiTokenSecretRef:
    name: authentik-api-token
    namespace: authentik-system
    key: token
  authorizationFlowSlug: "default-provider-authorization-implicit-consent"
  invalidationFlowSlug: "default-provider-invalidation-flow"
```

### OIDCPolicy (namespaced)

Protects HTTPRoutes with OIDC authentication:

```yaml
apiVersion: authentik-envoy-operator.io/v1alpha1
kind: OIDCPolicy
metadata:
  name: grafana-oidc
  namespace: monitoring
spec:
  providerRef:
    name: main
  targetRefs:
    - name: grafana-route
  oidc:
    allowedGroups:
      - admins
      - developers
    signingKey: "authentik Self-signed Certificate"
    propertyMappings:
      - "authentik default OAuth Mapping: OpenID 'openid'"
      - "authentik default OAuth Mapping: OpenID 'profile'"
      - "authentik default OAuth Mapping: OpenID 'email'"
    scopes:
      - openid
      - profile
      - email
    forwardAccessToken: true
    cookieConfig:
      namePrefix: "grafana"
```

## How It Works

1. The operator resolves the `AuthentikProvider` to get API credentials
2. It looks up groups, signing keys, and property mappings by name in Authentik
3. It derives redirect URIs from HTTPRoute hostnames
4. It creates/updates the OAuth2 provider and application in Authentik
5. It binds the specified groups to the application
6. It syncs the client secret to a Kubernetes Secret
7. It creates a SecurityPolicy per targetRef with:
   - OIDC configuration (issuer, client credentials, scopes)
   - JWT validation (JWKS endpoint, audience check)
   - Authorization rules (group-based access via JWT claims)

## Authentik API Token Permissions

The API token needs the following permissions:

- `authentik_core.view_application`, `add_application`, `change_application`, `delete_application`
- `authentik_providers_oauth2.view_oauth2provider`, `add_oauth2provider`, `change_oauth2provider`, `delete_oauth2provider`
- `authentik_policies.view_policybinding`, `add_policybinding`, `delete_policybinding`
- `authentik_flows.view_flow`
- `authentik_core.view_group`
- `authentik_crypto.view_certificatekeypair`
- `authentik_providers_oauth2.view_scopemapping`

## Metrics

The operator exposes Prometheus metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `authentik_operator_reconcile_duration_seconds` | Histogram | Reconcile loop duration |
| `authentik_operator_reconcile_errors_total` | Counter | Reconcile errors by type |
| `authentik_operator_policy_status` | Gauge | Policy status (1=ready, 0=not ready) |
| `authentik_operator_provider_connected` | Gauge | Provider connectivity (1=connected) |

## Development

```bash
# Run tests
make test

# Run locally against current kubeconfig
make run

# Build image
make docker-build IMG=registry.example.com/authentik-envoy-operator:latest
```

## License

Apache License 2.0
