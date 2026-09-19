# Authentik Envoy Operator

A Kubernetes operator that manages Authentik OAuth2 applications, optionally renders application-specific Kubernetes Secrets, and optionally protects HTTPRoutes with Envoy Gateway SecurityPolicy resources.

## How It Works

1. You create an `AuthentikProvider` (cluster-scoped) pointing to your Authentik instance
2. You create an `OIDCApplication` (namespaced); add `targetRefs` to also front HTTPRoutes with Envoy
3. The operator automatically:
    - Creates/adopts an OAuth2 Provider and Application in Authentik
    - References or creates the listed groups and binds them to the application
    - Renders an application Secret only when `spec.secretTemplate` is nonempty
    - Writes the fixed Envoy client-secret Secret only when `targetRefs` are set
    - Creates Envoy Gateway `SecurityPolicy` resources for each target HTTPRoute (only when `targetRefs` are set)

## Architecture

```
+-------------+     +------------------+     +----------------+
|OIDCApplicat.|---->|    Operator      |---->|   Authentik    |
|   (CRD)     |     |                  |     |  (OAuth2 API)  |
+-------------+     |  - Reconcile     |     +----------------+
                    |  - Watch changes |
+-------------+     |  - Cleanup       |     +----------------+
|AuthentikProv|---->|                  |---->| SecurityPolicy |
|   (CRD)     |     +------------------+     |  (Envoy GW)   |
+-------------+                              +----------------+
```

## Features

- Declarative OIDC configuration via Kubernetes CRDs
- Automatic Authentik resource lifecycle management (create, update, delete)
- Group-based access control with policy bindings (reference existing groups or create them)
- Standalone mode provisions Authentik without Envoy resources; application Secret output is independently opt-in through `secretTemplate`
- Envoy mode lets one OIDCApplication protect multiple HTTPRoutes through `targetRefs`
- Prometheus metrics for monitoring reconciliation health
- Finalizer-based cleanup when resources are deleted
- Watches on upstream resources (AuthentikProvider, HTTPRoute) for immediate re-reconciliation
