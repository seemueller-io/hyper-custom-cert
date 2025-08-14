# hyper-custom-cert

[![Crates.io](https://img.shields.io/crates/v/hyper-custom-cert.svg)](https://crates.io/crates/hyper-custom-cert)
[![docs.rs](https://img.shields.io/docsrs/hyper-custom-cert)](https://docs.rs/hyper-custom-cert)
[![CI](https://github.com/seemueller-io/hyper-custom-cert/actions/workflows/ci.yml/badge.svg)](https://github.com/seemueller-io/hyper-custom-cert/actions)

A reusable HTTP client builder API with clear, security‑focused feature flags for selecting your TLS backend and security posture.

This crate is derived from a reference implementation in this repository (under `reference-implementation/`), but is designed as a reusable library with a more robust and explicit configuration surface. Networking internals are intentionally abstracted for now; the focus is on a secure, ergonomic API.

## Features and TLS strategy

- Default: `native-tls`
  - Uses the operating system trust store via `hyper-tls`/`native-tls`.
  - Secure default for connecting to standard, publicly trusted endpoints.

- Optional: `rustls`
  - Uses `hyper-rustls`.
  - Activates the `with_root_ca_pem` method on the builder, allowing you to trust a custom Root CA (recommended approach for custom/private CAs).

- Optional: `insecure-dangerous`
  - Unlocks `insecure_accept_invalid_certs(true)` and `HttpClient::with_self_signed_certs()`.
  - IMPORTANT: This is for local development/testing only and must NEVER be used in production.

See SECURITY.md for a thorough discussion of these modes and when to use them.

## Quick start

- Default (native-tls):
  ```bash
  cargo build -p hyper-custom-cert
  cargo run -p hyper-custom-cert --example self-signed-certs
  ```

- With rustls (custom Root CA support):
  ```bash
  cargo build -p hyper-custom-cert --no-default-features --features rustls
  cargo run -p hyper-custom-cert --no-default-features --features rustls --example self-signed-certs
  ```

- Insecure (dangerous, dev only):
  ```bash
  # With native-tls
  cargo build -p hyper-custom-cert --features insecure-dangerous
  cargo run -p hyper-custom-cert --features insecure-dangerous --example self-signed-certs

  # With rustls
  cargo build -p hyper-custom-cert --no-default-features --features rustls,insecure-dangerous
  cargo run -p hyper-custom-cert --no-default-features --features rustls,insecure-dangerous --example self-signed-certs
  ```

## Builder API overview

```rust,ignore
use hyper_custom_cert::HttpClient;
use std::time::Duration;
use std::collections::HashMap;

let mut headers = HashMap::new();
headers.insert("x-app".into(), "demo".into());

let mut builder = HttpClient::builder()
    .with_timeout(Duration::from_secs(10))
    .with_default_headers(headers);

// When the `rustls` feature is enabled, you can add a custom Root CA:
#[cfg(feature = "rustls")]
{
    // Option 1: Load CA certificate from raw PEM bytes
    builder = builder.with_root_ca_pem(include_bytes!("../examples-data/root-ca.pem"));
    
    // Option 2: Load CA certificate from a file path
    builder = builder.with_root_ca_file("path/to/root-ca.pem");
    
    // Option 3: Using std::path::Path
    use std::path::Path;
    let ca_path = Path::new("certs/custom-ca.pem");
    builder = builder.with_root_ca_file(ca_path);
    
    // Option 4: Certificate pinning for additional security
    let pin1: [u8; 32] = [
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18
    ];
    let pin2: [u8; 32] = [
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
        0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    ];
    builder = builder.with_pinned_cert_sha256(vec![pin1, pin2]);
}

let client = builder.build();

// During local development only:
#[cfg(feature = "insecure-dangerous")]
{
    let dev_client = HttpClient::with_self_signed_certs();
    let dev_client2 = HttpClient::builder()
        .insecure_accept_invalid_certs(true)
        .build();
}
```

## Selecting features

- Native TLS (default):
  - `cargo add hyper-custom-cert` (or no extra flags if in this workspace)
  - `cargo build`

- Rustls:
  - `cargo build --no-default-features --features rustls`

- Insecure (dangerous, dev only):
  - With native TLS: `cargo build --features insecure-dangerous`
  - With rustls: `cargo build --no-default-features --features rustls,insecure-dangerous`

## WASM Support

This library's WASM build is **primarily intended for edge runtime environments** such as Cloudflare Workers, Deno Deploy, Vercel Edge Functions, and similar serverless edge computing platforms.

### Edge Runtime Usage (Primary Use Case)

Edge runtimes provide a more capable WASM environment compared to browsers, often supporting custom certificate configuration and advanced TLS features:

**Capabilities in Edge Runtimes:**
- **Custom Root CA Support:** Methods like `with_root_ca_pem()` and `with_root_ca_file()` are typically supported
- **Certificate Pinning:** The `with_pinned_cert_sha256()` method may be available depending on the runtime
- **Flexible TLS Configuration:** Full control over certificate validation and TLS settings
- **No Same-Origin Policy:** Direct network access without browser security restrictions

**Recommended Approach for Edge Runtimes:**
```rust,ignore
#[cfg(target_arch = "wasm32")]
{
    // For edge runtimes, full custom CA support is typically available
    #[cfg(feature = "rustls")]
    let client = HttpClient::builder()
        .with_timeout(Duration::from_secs(10))
        .with_root_ca_pem(include_bytes!("../certs/root-ca.pem"))
        .build();
    
    // Certificate pinning for additional security
    let pin: [u8; 32] = [/* your certificate SHA-256 hash */];
    let client_with_pinning = HttpClient::builder()
        .with_pinned_cert_sha256(vec![pin])
        .build();
}
```

**Popular Edge Runtime Platforms:**
- **Cloudflare Workers:** Full WASM support with network capabilities
- **Deno Deploy:** TypeScript/JavaScript runtime with WASM modules
- **Vercel Edge Functions:** Next.js edge runtime environment  
- **Fastly Compute@Edge:** High-performance edge computing platform
- **AWS Lambda@Edge:** Serverless edge functions

### Browser Usage (Limited Support)

When running in browser environments, WASM operates under significant security restrictions:

**Browser Limitations:**
- **No Custom Root CA Support:** Methods like `with_root_ca_pem()` and `with_root_ca_file()` may return `WasmNotImplemented` errors
- **No Certificate Pinning:** The `with_pinned_cert_sha256()` method is not available in browser environments
- **Browser-Controlled Trust:** All certificate validation is handled by the browser's built-in certificate store
- **Same-Origin Policy:** Cross-origin requests are subject to CORS policies and browser security models

**Browser Development Guidance:**
```rust,ignore
#[cfg(target_arch = "wasm32")]
{
    // For browser WASM, rely on browser's built-in certificate validation
    let client = HttpClient::builder()
        .with_timeout(Duration::from_secs(10))
        .build();
}
```

For development with self-signed certificates in browsers, you'll need to install certificates in the browser's certificate store rather than configuring them programmatically.

### Environment Detection

To handle both edge runtime and browser environments gracefully:

```rust,ignore
#[cfg(target_arch = "wasm32")]
{
    // Attempt edge runtime configuration, fall back to basic setup
    let mut builder = HttpClient::builder()
        .with_timeout(Duration::from_secs(10));
    
    #[cfg(feature = "rustls")]
    {
        // Try to use custom CA - this will work in edge runtimes
        // but may fail in browsers
        match std::panic::catch_unwind(|| {
            builder.with_root_ca_pem(include_bytes!("../certs/root-ca.pem"))
        }) {
            Ok(configured_builder) => builder = configured_builder,
            Err(_) => {
                // Fallback for browser environments
                eprintln!("Custom CA configuration not supported in this WASM environment");
            }
        }
    }
    
    let client = builder.build();
}
```

### Production Considerations

**For Edge Runtimes:**
- Leverage full TLS configuration capabilities available in your edge platform
- Use custom CAs and certificate pinning for enhanced security
- Test certificate handling across different edge runtime providers
- Consider platform-specific TLS optimizations

**For Browser Applications:**
- Always use proper SSL/TLS certificates from trusted CAs
- Consider using Let's Encrypt or other automated certificate management solutions
- Document any certificate requirements clearly for end users
- Plan for browser security policy limitations

## Security Notes

- Prefer the default `native-tls` or the `rustls` feature for production.
- The `insecure-dangerous` feature must never be enabled in production; it bypasses certificate validation and exposes you to active MITM risk.
- On WASM platforms, certificate handling varies by environment: edge runtimes typically support full custom CA configuration, while browser environments manage certificate validation through built-in certificate stores.
