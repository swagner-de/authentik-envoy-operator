# Security Policy

## Supported versions

This project is under active development (`v1alpha1`). Security fixes are applied
to the latest released version and the `main` branch.

## Reporting a vulnerability

Please report security vulnerabilities privately rather than opening a public
issue.

- Use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  ("Report a vulnerability" under the repository's **Security** tab), or
- Contact the maintainers directly.

Please include:

- A description of the vulnerability and its impact
- Steps to reproduce or a proof of concept
- Affected version(s)

We will acknowledge your report, investigate, and coordinate a fix and
disclosure timeline with you. Please do not disclose the issue publicly until a
fix is available.

## Handling secrets

This operator reads Authentik API tokens and OAuth2 client secrets from
Kubernetes Secrets and renders them into application Secrets. When reporting
issues or sharing logs, always redact tokens, client secrets, and other
credentials.
