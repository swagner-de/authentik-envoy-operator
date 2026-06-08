# CRD Reference

## AuthentikProvider

**Scope:** Cluster

Represents a connection to an Authentik instance.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `spec.host` | string | Yes | Authentik instance URL (e.g., `https://authentik.example.com`) |
| `spec.apiTokenSecretRef.name` | string | Yes | Name of the Secret containing the API token |
| `spec.apiTokenSecretRef.namespace` | string | Yes | Namespace of the Secret |
| `spec.apiTokenSecretRef.key` | string | Yes | Key within the Secret data |
| `spec.authorizationFlowSlug` | string | Yes | Slug of the authorization flow in Authentik |
| `spec.invalidationFlowSlug` | string | Yes | Slug of the invalidation flow in Authentik |

### Status

| Field | Type | Description |
|-------|------|-------------|
| `status.conditions[].type` | string | `Connected` — whether the operator can reach Authentik |
| `status.authorizationFlowUID` | string | Resolved UUID of the authorization flow |
| `status.invalidationFlowUID` | string | Resolved UUID of the invalidation flow |

---

## OIDCPolicy

**Scope:** Namespaced

Declares OIDC protection for one or more HTTPRoutes.

### Spec

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `spec.providerRef.name` | string | Yes | Name of the AuthentikProvider to use |
| `spec.targetRefs[].name` | string | Yes | Name of an HTTPRoute in the same namespace |
| `spec.oidc.allowedGroups` | []string | Yes | Authentik group names allowed access |
| `spec.oidc.scopes` | []string | No | OAuth2 scopes (default: `openid`, `profile`, `email`) |
| `spec.oidc.signingKey` | string | Yes | Name of the certificate key pair in Authentik |
| `spec.oidc.propertyMappings` | []string | Yes | Names of scope mappings in Authentik |
| `spec.oidc.forwardAccessToken` | bool | No | Forward access token to upstream (default: `false`) |
| `spec.oidc.cookieConfig.namePrefix` | string | No | Custom cookie name prefix |

### Status

| Field | Type | Description |
|-------|------|-------------|
| `status.conditions[].type` | string | `Ready` — overall reconciliation status |
| `status.authentik.providerID` | int | Authentik OAuth2 Provider PK |
| `status.authentik.clientID` | string | OAuth2 client ID |
| `status.authentik.applicationSlug` | string | Authentik application slug |
| `status.authentik.applicationID` | string | Authentik application PK |
| `status.authentik.policyBindingIDs` | []string | Created policy binding PKs |
| `status.authentik.boundGroups` | []string | Currently bound group names |
| `status.securityPolicies[].name` | string | Created SecurityPolicy name |
| `status.securityPolicies[].targetRoute` | string | Associated HTTPRoute name |
| `status.secretName` | string | Name of the client secret Secret |

---

## Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `authentik_operator_reconcile_duration_seconds` | Histogram | name, namespace | Time spent in reconciliation |
| `authentik_operator_reconcile_errors_total` | Counter | name, namespace, reason | Reconciliation error count |
| `authentik_operator_policy_status` | Gauge | name, namespace | 1 = ready, 0 = not ready |
