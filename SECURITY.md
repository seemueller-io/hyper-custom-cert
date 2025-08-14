# Security Policy for hyper-custom-cert

This repository contains a reusable HTTP client crate that emphasizes a secure-by-default configuration with explicit, opt-in feature flags for alternative modes. This document explains the security implications of each feature and how to use the library safely in production.

## Summary of TLS Modes

- Default: `native-tls`
  - Uses the operating system trust store via `hyper-tls`/`native-tls`.
  - Recommended and secure default for connecting to publicly trusted endpoints.

- Optional: `rustls`
  - Uses `hyper-rustls`.
  - Enables `HttpClientBuilder::with_root_ca_pem(...)` so you can trust a custom/private Root CA (e.g., your organization’s internal CA). This is the recommended approach when you must connect to services with certificates that aren’t publicly trusted.

- Optional: `insecure-dangerous`
  - Enables `HttpClientBuilder::insecure_accept_invalid_certs(true)` and `HttpClient::with_self_signed_certs()`.
  - Extremely dangerous and intended ONLY for local development and testing.
  - Disables certificate validation and exposes you to active man-in-the-middle attacks if used against untrusted networks or in production.

## Production Guidance

- Prefer the default `native-tls` unless you have a specific need to trust a private/custom CA.
- When you must trust a private CA, build with the `rustls` feature and provide your CA certificate via `with_root_ca_pem(...)`. Ensure the provided PEM is the correct Root CA, securely distributed and stored.
- Never enable `insecure-dangerous` in production. It bypasses certificate validation entirely.
- Keep your dependencies up-to-date. Watch for advisories affecting TLS libraries (native-tls, hyper-tls, rustls, hyper-rustls).

## WebAssembly (wasm32) Considerations

Browsers do not allow web applications to programmatically install or trust custom Certificate Authorities. Trust decisions are enforced by the browser and the underlying OS. As a result, operations that imply adding custom CA roots are intentionally unsupported in wasm targets and may return errors.

## Reporting a Vulnerability

If you discover a security vulnerability, please:

1. Do not open a public issue immediately.
2. Email the maintainers at security@williamseemueller.dev with a detailed description and steps to reproduce.
3. We will acknowledge receipt within 3 business days and strive to provide a timeline for a fix.

If you do not receive a timely response, you may escalate by opening a minimal public issue that avoids disclosing sensitive details.

## Hardening Checklist

- Use feature flags intentionally. Avoid enabling `insecure-dangerous` except in isolated, local environments.
- Pin and audit dependencies using `cargo audit` in CI.
- Rotate and protect your custom CA material. Limit developer access and store PEMs securely.
- Prefer short timeouts and explicit defaults via the builder to reduce exposure to hanging connections.
