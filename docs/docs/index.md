# Authentik Envoy Operator

A Kubernetes operator that automates OIDC authentication for services behind Envoy Gateway by managing Authentik OAuth2 providers and Envoy Gateway SecurityPolicy resources.

## How It Works

1. You create an `AuthentikProvider` (cluster-scoped) pointing to your Authentik instance
2. You create an `OIDCPolicy` (namespaced) referencing HTTPRoutes to protect
3. The operator automatically:
    - Creates an OAuth2 Provider in Authentik
    - Creates an Application in Authentik
    - Binds allowed groups to the application
    - Syncs the client secret to a Kubernetes Secret
    - Creates Envoy Gateway `SecurityPolicy` resources for each target HTTPRoute

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌────────────────┐
│ OIDCPolicy  │────▶│    Operator      │────▶│   Authentik    │
│   (CRD)     │     │                  │     │  (OAuth2 API)  │
└─────────────┘     │  - Reconcile     │     └────────────────┘
                    │  - Watch changes │
┌─────────────┐     │  - Cleanup       │     ┌────────────────┐
│AuthentikProv│────▶│                  │────▶│ SecurityPolicy │
│   (CRD)     │     └──────────────────┘     │  (Envoy GW)   │
└─────────────┘                              └────────────────┘
```

## Features

- Declarative OIDC configuration via Kubernetes CRDs
- Automatic Authentik resource lifecycle management (create, update, delete)
- Group-based access control with policy bindings
- Multi-route support (one OIDCPolicy can protect multiple HTTPRoutes)
- Prometheus metrics for monitoring reconciliation health
- Finalizer-based cleanup when resources are deleted
- Watches on upstream resources (AuthentikProvider, HTTPRoute) for immediate re-reconciliation
