# Getting Started

## Prerequisites

- Kubernetes 1.28+
- [Envoy Gateway](https://gateway.envoyproxy.io/) 1.0+ `SecurityPolicy` CRDs and Gateway API `HTTPRoute` CRDs. The manager currently registers watches for both APIs at startup, even for standalone applications; Envoy functionality is used only with `targetRefs`.
- [Authentik](https://goauthentik.io/) instance with API access
- Helm 3.x

## Installation

### Via Helm

The chart is Kubebuilder-generated and lives at `dist/chart` (published as an OCI artifact on release).

```bash
helm install authentik-envoy-operator ./dist/chart \
  --namespace authentik-envoy-operator \
  --create-namespace \
  --set webhook.enabled=false \
  --set certManager.enabled=false \
  --set metrics.secure=false
```

The chart defaults `manager.image.repository` to `ghcr.io/authentik-envoy-operator/authentik-envoy-operator` and the tag to the chart's `appVersion`; override with `--set manager.image.repository=...` / `--set manager.image.tag=...` if you host the image elsewhere.

> **Note:** `metrics.secure` defaults to `true`, which serves metrics over HTTPS using a cert-manager-provisioned serving certificate. When you disable cert-manager (as above) you must also set `metrics.secure=false`, otherwise the metrics endpoint has no serving certificate. For production, keep cert-manager enabled and leave secure metrics on.

### Authentik API Token

Create an API token in Authentik with the following permissions:

- Read/Write access to **Providers** (OAuth2)
- Read/Write access to **Applications**
- Read/Write access to **Policy Bindings**
- Read access to **Groups**, plus add/delete access when using `groups[].create: true` or `groups[].cleanup: true`
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

### 2. Create an OIDCApplication

With `targetRefs` (Envoy-fronted):

```yaml
apiVersion: authentik-envoy-operator.io/v1alpha1
kind: OIDCApplication
metadata:
  name: my-app
  namespace: default
spec:
  providerRef:
    name: main
  displayName: "My App"
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
  targetRefs:
    - name: my-app-route
```

Use an asymmetric RSA or EC `signingKey` so tokens can be verified through JWKS.

Omit `targetRefs` for **standalone** mode (no Envoy resources). Native apps need explicit `redirectURIs` for functional login because there are no route-derived callbacks; the controller does not reject an omitted list. To also create an application Secret, add a nonempty template; its name defaults to `<name>-oidc`:

```yaml
spec:
  # ...
  redirectURIs:
    - "https://paperless.example.com/accounts/oidc/authentik/login/callback/"
  secretTemplate:
    # quote emits a JSON string, including its surrounding quotes.
    PAPERLESS_SOCIALACCOUNT_PROVIDERS: >-
      [{"provider":"openid_connect","name":"Authentik","settings":{"server_url":{{ .DiscoveryURL | quote }},"client_id":{{ .ClientID | quote }},"secret":{{ .ClientSecret | quote }}}}]
```

The Secret contains exactly the keys in `secretTemplate`; the operator does not add or merge a fixed credential schema.

### Migrate the former fixed-schema Secret

The application Secret is no longer created implicitly. To preserve the exact
former nine-key schema during an upgrade, add this template. Omit `secretName`
to retain the default `<name>-oidc` name, or set it to the existing Secret name:

```yaml
spec:
  # ...
  secretTemplate:
    client-id: "{{ .ClientID }}"
    client-secret: "{{ .ClientSecret }}"
    issuer: "{{ .Issuer }}"
    discovery-url: "{{ .DiscoveryURL }}"
    authorization-endpoint: "{{ .AuthorizationEndpoint }}"
    token-endpoint: "{{ .TokenEndpoint }}"
    userinfo-endpoint: "{{ .UserinfoEndpoint }}"
    jwks-uri: "{{ .JWKSURI }}"
    end-session-endpoint: "{{ .EndSessionEndpoint }}"
```

### 3. Verify

```bash
# Check AuthentikProvider connectivity
kubectl get authentikproviders

# Check OIDCApplication status
kubectl get oidcapplications -A

# Check created SecurityPolicies
kubectl get securitypolicies -A
```

## What Happens Next

The operator will:

1. Resolve the signing key and property mappings, and reference/create the listed groups in Authentik
2. Create (or adopt) an OAuth2 Provider named `<namespace>-<name>` (override via `spec.slug`)
3. Create an Application with the same slug (display name from `spec.displayName`)
4. Bind the listed groups to the application
5. Build redirect URIs from `spec.redirectURIs` plus each referenced HTTPRoute's hostnames
6. If `secretTemplate` is nonempty, render its entries into the application Secret in the same namespace
7. If `targetRefs` are set, write `<name>-envoy-oidc` with exactly the `client-secret` key and create a `SecurityPolicy` per target HTTPRoute that references it
