# Changelog

## [0.2.3](https://github.com/swagner-de/authentik-envoy-operator/compare/v0.2.2...v0.2.3) (2026-09-23)


### Dependencies

* **deps:** update actions/setup-python action to v7 ([8d89d58](https://github.com/swagner-de/authentik-envoy-operator/commit/8d89d588d60382dd109c72ea7ecfaacbe6c89814))
* **deps:** update actions/upload-pages-artifact action to v5 ([bcac1e5](https://github.com/swagner-de/authentik-envoy-operator/commit/bcac1e5bf649bf74ab3e86a20f9b0be590eb4dfc))

## [0.2.2](https://github.com/swagner-de/authentik-envoy-operator/compare/v0.2.1...v0.2.2) (2026-09-22)


### Bug Fixes

* adapt to dependency API changes ([d0701db](https://github.com/swagner-de/authentik-envoy-operator/commit/d0701db4e524ddf4b1814997a0dcd6e2e939f903))
* **deps:** update go modules ([45f6fc2](https://github.com/swagner-de/authentik-envoy-operator/commit/45f6fc2b1186ecb8bba33658f1574503be30f641))
* specify repository for release auto-merge ([f3ac10a](https://github.com/swagner-de/authentik-envoy-operator/commit/f3ac10a4054cf46ab57e809d98d1c90aa7266ab7))


### Dependencies

* **deps:** update actions/checkout action to v7 ([20b77b6](https://github.com/swagner-de/authentik-envoy-operator/commit/20b77b6d47c68838577d16edc51e7f896456643a))
* **deps:** update actions/deploy-pages action to v5 ([e523716](https://github.com/swagner-de/authentik-envoy-operator/commit/e523716a5677c6c7d12a199b42f52e2eb0b444db))
* **deps:** update actions/setup-go action to v7 ([bce721f](https://github.com/swagner-de/authentik-envoy-operator/commit/bce721ffa9183975878399ac42b49c94947d4b78))
* **deps:** update github-actions ([#3](https://github.com/swagner-de/authentik-envoy-operator/issues/3)) ([0272859](https://github.com/swagner-de/authentik-envoy-operator/commit/0272859882881a5792a802735f7517fa96e070c3))
* **deps:** update golang docker tag to v1.27 ([63a4b49](https://github.com/swagner-de/authentik-envoy-operator/commit/63a4b493ff68ef5ee4d444ad1a14f90d92a08516))

## [0.2.1](https://github.com/swagner-de/authentik-envoy-operator/compare/v0.2.0...v0.2.1) (2026-09-20)


### Bug Fixes

* remove zero-width spaces breaking release workflow expressions ([e316798](https://github.com/swagner-de/authentik-envoy-operator/commit/e316798dc467422703845fd3ec6fa28c9e6fbc48))

## [0.2.0](https://github.com/swagner-de/authentik-envoy-operator/compare/v0.1.0...v0.2.0) (2026-09-20)


### Features

* add Authentik API client with types and HTTP transport ([d243a38](https://github.com/swagner-de/authentik-envoy-operator/commit/d243a38d67ec19c18921c0ea565cd80652704135))
* add Authentik flow and group lookup ([6ef7713](https://github.com/swagner-de/authentik-envoy-operator/commit/6ef77134daf9b520428b657c3766cba1abd8a06d))
* add Authentik provider, application, and policy binding CRUD ([3d141f3](https://github.com/swagner-de/authentik-envoy-operator/commit/3d141f3927a802afb93c3f153c8c0bf092ccbf03))
* add CI/CD workflows, Renovate config ([b9e99d5](https://github.com/swagner-de/authentik-envoy-operator/commit/b9e99d5f1f67c6bee447568048922a5e819a21be))
* add Helm chart for authentik-envoy-operator ([b1b4610](https://github.com/swagner-de/authentik-envoy-operator/commit/b1b4610459e9e306c8134a56dda2550e947fa48f))
* add OIDCPolicy validating webhook ([4a3f700](https://github.com/swagner-de/authentik-envoy-operator/commit/4a3f700b82b530611e7bd0b2eefe21b6668c023c))
* add Prometheus metric definitions ([381cbf6](https://github.com/swagner-de/authentik-envoy-operator/commit/381cbf6a177b5b5be8106c822d346b4873efd974))
* add SecurityPolicy builder with cookie name derivation ([c00e39a](https://github.com/swagner-de/authentik-envoy-operator/commit/c00e39a96ff63d70f2a10c690720a5aef29624ba))
* add signing key, property mappings, and grant types to OIDC provider ([c26a9c5](https://github.com/swagner-de/authentik-envoy-operator/commit/c26a9c533bd2221b29838f2fc080f639561ed7a9))
* define AuthentikProvider and OIDCPolicy CRD types ([dfcde19](https://github.com/swagner-de/authentik-envoy-operator/commit/dfcde19760ef8c92c9c90bde0d6dfa6899a6720b))
* implement AuthentikProvider controller with connectivity check ([cf5df04](https://github.com/swagner-de/authentik-envoy-operator/commit/cf5df0415e62856d2c8c60449705a052c63896d4))
* implement OIDCPolicy controller with full reconciliation loop ([f3ef90d](https://github.com/swagner-de/authentik-envoy-operator/commit/f3ef90dd0a5f8229c8bac40c516d5a5c24ce2298))
* replace OIDCPolicy with OIDCApplication ([7c90563](https://github.com/swagner-de/authentik-envoy-operator/commit/7c905636a3fe06ac2ca4534d8d28598070f68977))
* scaffold kubebuilder project with AuthentikProvider and OIDCPolicy CRDs ([910b239](https://github.com/swagner-de/authentik-envoy-operator/commit/910b2398ec65378880bab4c21291cca4726801f5))


### Bug Fixes

* add watches, tighten RBAC, order-insensitive group comparison ([3ee54dd](https://github.com/swagner-de/authentik-envoy-operator/commit/3ee54ddf8f7eba96ff50085409d470359d484146))
* delete orphaned SecurityPolicies when targetRefs shrinks ([6c040fc](https://github.com/swagner-de/authentik-envoy-operator/commit/6c040fcb8efa5861a678e19f7177ed702588e680))
* regenerate deepcopy for BoundGroups and PropertyMappings ([a07b439](https://github.com/swagner-de/authentik-envoy-operator/commit/a07b439401bf096926198143de5ba17ea8d58527))
* resolve golangci-lint findings ([807c33f](https://github.com/swagner-de/authentik-envoy-operator/commit/807c33fbf1c696326a5e7a22360896db8c1d38d8))
* return errors from cleanup() to retry failed Authentik deletions ([9640642](https://github.com/swagner-de/authentik-envoy-operator/commit/9640642645e64a55be5fb8e4c376b6ae0fbe1ccf))
* skip Authentik writes when remote state already matches desired ([a5cbbac](https://github.com/swagner-de/authentik-envoy-operator/commit/a5cbbacf564551d3a935ea1df301f99430d75e6d))
