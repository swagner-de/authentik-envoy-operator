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
| `spec.authorizationFlowSlug` | string | No | Slug of the authorization flow (default: `default-provider-authorization-implicit-consent`) |
| `spec.invalidationFlowSlug` | string | No | Slug of the invalidation flow (default: `default-provider-invalidation-flow`) |

### Status

| Field | Type | Description |
|-------|------|-------------|
| `status.conditions[].type` | string | `Connected` - whether the operator can reach Authentik |
| `status.authorizationFlowUID` | string | Resolved UUID of the authorization flow |
| `status.invalidationFlowUID` | string | Resolved UUID of the invalidation flow |

---

## OIDCApplication

**Scope:** Namespaced

Provisions an Authentik OAuth2 application and groups, optionally renders an
application Secret, and optionally fronts HTTPRoutes with an Envoy Gateway
`SecurityPolicy`. Secret templating and Envoy protection are independent.

### Spec

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `spec.providerRef.name` | string | Yes | Name of the AuthentikProvider to use |
| `spec.displayName` | string | No | Authentik application name (default: `metadata.name`) |
| `spec.slug` | string | No | Stable identifier = Authentik slug + client_id + provider name (default: `<namespace>-<name>`). Immutable. |
| `spec.signingKey` | string | Yes | Name of the certificate key pair in Authentik. Use an asymmetric RSA or EC keypair for JWKS verification. |
| `spec.propertyMappings` | []string | No | Names of scope mappings in Authentik. Include one that emits the `groups` claim. |
| `spec.scopes` | []string | No | OAuth2 scopes (default: `openid`, `profile`). Must contain `openid` if set. |
| `spec.forwardAccessToken` | bool | No | Forward access token to upstream (default: `true`) |
| `spec.subMode` | string | No | Authentik `sub` claim mode (passthrough) |
| `spec.includeClaimsInIDToken` | bool | No | Include claims in the ID token (default: `true`) |
| `spec.accessTokenValidity` | string | No | Access token lifetime (Authentik timedelta, e.g. `minutes=10`) |
| `spec.refreshTokenValidity` | string | No | Refresh token lifetime (e.g. `days=30`) |
| `spec.accessCodeValidity` | string | No | Authorization code lifetime (e.g. `minutes=1`) |
| `spec.groups[].name` | string | Yes | Authentik group name (at least one group required) |
| `spec.groups[].create` | bool | No | Create the group if missing (default: `false`; it must already exist) |
| `spec.groups[].cleanup` | bool | No | Delete the group on OIDCApplication deletion, if the operator created it (default: `false`) |
| `spec.redirectURIs` | []string | No | Explicit redirect URIs. Native apps need callback URIs here for functional login because standalone mode has no route-derived callbacks; omission is not rejected. |
| `spec.cookieConfig.namePrefix` | string | No | Cookie name prefix (default: `metadata.name`) |
| `spec.cookieConfig.domain` | string | No | Cookie domain |
| `spec.cookieConfig.sameSite` | string | No | `Lax` (default), `Strict`, or `None` |
| `spec.appMeta.launchURL` | string | No | Authentik launcher URL (`meta_launch_url`) |
| `spec.appMeta.description` | string | No | Authentik launcher description |
| `spec.appMeta.publisher` | string | No | Authentik launcher publisher |
| `spec.appMeta.icon` | string | No | Authentik launcher icon URL |
| `spec.appMeta.openInNewTab` | bool | No | Open the launcher link in a new tab |
| `spec.appMeta.group` | string | No | Authentik application category |
| `spec.targetRefs[].group` | string | No | Route API group (default: `gateway.networking.k8s.io`) |
| `spec.targetRefs[].kind` | string | No | Route kind (default: `HTTPRoute`) |
| `spec.targetRefs[].name` | string | Yes | Route name in the same namespace |
| `spec.secretName` | string | No | Application Secret name. Used only with a nonempty `secretTemplate`; then defaults to `<name>-oidc`. It does not affect the Envoy Secret. |
| `spec.secretTemplate` | map[string]string | No | Application Secret data keys and Go templates. A nonempty map enables the application Secret, whose data is exactly these rendered entries. |

### Status

| Field | Type | Description |
|-------|------|-------------|
| `status.conditions[].type` | string | `Ready` - overall reconciliation status |
| `status.authentik.providerID` | int | Authentik OAuth2 Provider PK |
| `status.authentik.clientID` | string | OAuth2 client ID |
| `status.authentik.applicationSlug` | string | Authentik application slug |
| `status.authentik.applicationID` | string | Authentik application PK |
| `status.authentik.policyBindingIDs` | []string | Created policy binding PKs |
| `status.authentik.boundGroups` | []string | Currently bound group names |
| `status.authentik.createdGroups` | []string | Groups the operator created (cleanup candidates) |
| `status.securityPolicies[].name` | string | Created SecurityPolicy name |
| `status.securityPolicies[].targetRoute` | string | Associated HTTPRoute name |
| `status.secretName` | string | Application Secret name; empty when `spec.secretTemplate` is empty. This never reports the Envoy Secret. |

### Secret Outputs

| `secretTemplate` | `targetRefs` | Secret output | SecurityPolicy output |
|------------------|--------------|---------------|-----------------------|
| Empty | Empty | None | None |
| Nonempty | Empty | Application Secret only | None |
| Empty | Nonempty | Fixed `<name>-envoy-oidc` Secret only | One per targetRef |
| Nonempty | Nonempty | Application Secret and fixed Envoy Secret | One per targetRef |

The application Secret defaults to `<name>-oidc`, or `spec.secretName` when set,
and contains exactly the `spec.secretTemplate` entries. There is no merge or
fixed schema. The Envoy Secret is independent: `targetRefs` causes the operator
to create `<name>-envoy-oidc` with exactly the `client-secret` key, and each
generated `SecurityPolicy` references it. Its name cannot be overridden.

An application Secret name that collides with the fixed Envoy Secret name is
rejected. The operator also refuses to take over either desired Secret when it
is already controlled by another resource.

### Secret Template Context

Each template is rendered with these nine case-sensitive fields:

| Field | Value |
|-------|-------|
| `.ClientID` | OAuth2 client ID |
| `.ClientSecret` | OAuth2 client secret |
| `.Issuer` | Issuer URL from OIDC discovery |
| `.DiscoveryURL` | OIDC discovery document URL |
| `.AuthorizationEndpoint` | Authorization endpoint from discovery |
| `.TokenEndpoint` | Token endpoint from discovery |
| `.UserinfoEndpoint` | UserInfo endpoint from discovery |
| `.JWKSURI` | JWKS URI from discovery |
| `.EndSessionEndpoint` | End-session endpoint from discovery |

The operator provides four custom functions: `quote`, `toJson`, `trimPrefix`,
and `trimSuffix`. Normal Go `text/template` actions and built-in functions remain
available, but only these four custom functions are guaranteed and documented.
All four work in pipelines: `quote` converts its input to a string and
JSON-quotes it, `toJson` JSON-encodes its input, and the trim functions take the
prefix or suffix first so expressions such as
`{{ .Issuer | trimPrefix "https://" | trimSuffix "/" }}` work naturally.

Rendering is atomic. If any entry has an invalid template, `Ready` becomes
`False` with reason `SecretSyncFailed`, the last valid Secret remains unchanged,
and template context values are not included in logs or the condition message. Authentik
may omit an existing provider's client secret; in that case application Secret
entries that depend on `.ClientSecret` retain their previous bytes by key while
entries that do not are refreshed. A newly named dependent key has no prior
value and causes reconciliation to fail. The Envoy Secret independently retains
only its own existing `client-secret`; neither Secret supplies raw credentials
to the other.

### Migration And Lifecycle

The old implicit, fixed-schema application Secret has been removed. Users who
need an application Secret must define `spec.secretTemplate`; see the
[copyable nine-key compatibility template](getting-started.md#migrate-the-former-fixed-schema-secret).
Removing the template deletes the operator-owned application Secret and clears
`status.secretName`. Changing `spec.secretName` creates and validates the new
Secret before deleting the old operator-owned Secret; the status then records
the new name.

---

## Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `oidcapplication_reconcile_duration_seconds` | Histogram | name, namespace | Time spent in reconciliation |
| `oidcapplication_reconcile_errors_total` | Counter | name, namespace, error_type | Reconciliation error count |
| `oidcapplication_status` | Gauge | name, namespace | 1 = ready, 0 = not ready |
| `authentikprovider_connected` | Gauge | name | 1 = connected |
| `authentik_api_requests_total` | Counter | method, endpoint, status | Authentik API requests |
| `authentik_api_request_duration_seconds` | Histogram | method, endpoint | Authentik API latency |
