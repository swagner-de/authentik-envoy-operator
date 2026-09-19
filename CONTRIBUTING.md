# Contributing

Thanks for your interest in improving the Authentik Envoy Operator.

## Development setup

Prerequisites:

- Go (matching the version in `go.mod`)
- `make`
- A Kubernetes cluster for e2e tests ([Kind](https://kind.sigs.k8s.io/) is recommended)

Common workflows:

```bash
make test        # Run unit tests (envtest); excludes e2e
make lint        # Run the configured linter
make lint-fix    # Auto-fix lint issues where possible
make run         # Run the manager locally against your current kubeconfig
```

## Making changes

- This project is scaffolded with [Kubebuilder](https://book.kubebuilder.io). Do
  not hand-edit generated files (`config/crd/bases/*`, `config/rbac/role.yaml`,
  `**/zz_generated.*`, `PROJECT`).
- After editing `*_types.go` or kubebuilder markers, run `make manifests generate`.
- After editing Go code, run `make lint-fix` and `make test`.
- Keep the `// +kubebuilder:scaffold:*` markers intact.

## Pull requests

1. Fork the repository and create a topic branch.
2. Ensure `make lint` and `make test` pass.
3. Ensure generated artifacts are up to date (`make manifests generate` produces
   no diff). CI enforces this.
4. Write a clear description of what changed and why.

## Reporting bugs

Open an issue with steps to reproduce, the operator version, and relevant logs
(`kubectl logs -n <namespace> deployment/<manager> -c manager`). Please redact
any secrets or tokens.

## License

By contributing, you agree that your contributions will be licensed under the
[Apache License 2.0](LICENSE).
