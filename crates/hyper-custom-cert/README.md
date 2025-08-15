# hyper-custom-cert

[![Crates.io](https://img.shields.io/crates/v/hyper-custom-cert.svg)](https://crates.io/crates/hyper-custom-cert)
[![Documentation](https://docs.rs/hyper-custom-cert/badge.svg)](https://docs.rs/hyper-custom-cert)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)

A small, ergonomic HTTP client wrapper around hyper with optional support for custom Root CAs and a dev-only insecure mode for self-signed certificates.

## Features

- **Secure by Default**: Uses the operating system's native trust store via `native-tls`
- **Custom CA Support**: Optional `rustls` feature for connecting to services with custom Certificate Authorities
- **Development Mode**: Optional `insecure-dangerous` feature for testing with self-signed certificates (⚠️ **NEVER use in production**)
- **WebAssembly Compatible**: Proper WASM support with appropriate security constraints
- **Certificate Pinning**: Advanced security feature for production environments
- **Builder Pattern**: Ergonomic configuration with sensible defaults

## Quick Start

`cargo add hyper-custom-cert`

### Basic Usage (Secure Default)

```rust
use hyper_custom_cert::HttpClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Uses OS trust store by default - secure for public HTTPS endpoints
    let client = HttpClient::new();
    
    // Make requests to publicly trusted endpoints
    client.request("https://httpbin.org/get").await?;
    
    Ok(())
}
```

### Custom Root CA (Production)

For connecting to services with custom/private Certificate Authorities:

```toml
[dependencies]
hyper-custom-cert = { version = "0.1.0", features = ["rustls"] }
```

```rust
use hyper_custom_cert::HttpClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load your organization's Root CA
    let client = HttpClient::builder()
        .with_root_ca_file("path/to/your-org-root-ca.pem")
        .build();
    
    // Now you can connect to services signed by your custom CA
    client.request("https://internal.your-org.com/api").await?;
    
    Ok(())
}
```

### Certificate Pinning (Enhanced Security)

For high-security environments where you want to pin specific certificates:

```rust
use hyper_custom_cert::HttpClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // SHA-256 fingerprints of certificates you want to accept
    let pin1 = [0x12, 0x34, /* ... 30 more bytes */];
    let pin2 = [0xab, 0xcd, /* ... 30 more bytes */];
    
    let client = HttpClient::builder()
        .with_pinned_cert_sha256(vec![pin1, pin2])
        .build();
    
    // Only accepts connections to certificates matching the pins
    client.request("https://secure-api.example.com").await?;
    
    Ok(())
}
```

### Development/Testing Only (⚠️ Dangerous)

**WARNING**: This mode disables certificate validation. Only use for local development and testing.

```toml
[dependencies]
hyper-custom-cert = { version = "0.1.0", features = ["insecure-dangerous"] }
```

```rust
use hyper_custom_cert::HttpClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ⚠️ EXTREMELY DANGEROUS - Only for local development
    let client = HttpClient::builder()
        .insecure_accept_invalid_certs(true)
        .build();
    
    // Can connect to self-signed certificates (NOT for production!)
    client.request("https://localhost:8443").await?;
    
    Ok(())
}
```

## Configuration Options

### Builder Methods

```rust
use hyper_custom_cert::HttpClient;
use std::time::Duration;
use std::collections::HashMap;

let mut headers = HashMap::new();
headers.insert("User-Agent".to_string(), "MyApp/1.0".to_string());

let client = HttpClient::builder()
    .with_timeout(Duration::from_secs(30))
    .with_default_headers(headers)
    .with_root_ca_file("custom-ca.pem")  // Requires 'rustls' feature
    .build();
```

### Available Methods

| Method | Feature Required | Description |
|--------|-----------------|-------------|
| `new()` | None | Creates client with OS trust store (secure default) |
| `builder()` | None | Returns a builder for custom configuration |
| `with_timeout(Duration)` | None | Sets request timeout |
| `with_default_headers(HashMap)` | None | Sets default headers for all requests |
| `with_root_ca_pem(&[u8])` | `rustls` | Adds custom CA from PEM bytes |
| `with_root_ca_file(Path)` | `rustls` | Adds custom CA from PEM file |
| `with_pinned_cert_sha256(Vec<[u8; 32]>)` | `rustls` | Enables certificate pinning |
| `insecure_accept_invalid_certs(bool)` | `insecure-dangerous` | ⚠️ Disables certificate validation |
| `with_self_signed_certs()` | `insecure-dangerous` | ⚠️ Convenience for self-signed certs |

## Feature Flags

### `native-tls` (Default)

- **Default**: ✅ Enabled
- **Security**: ✅ Secure - Uses OS trust store
- **Use Case**: Public HTTPS endpoints with standard certificates
- **Dependencies**: `hyper-tls`, `native-tls`

### `rustls`

- **Default**: ❌ Disabled
- **Security**: ✅ Secure - Custom CA validation
- **Use Case**: Private/custom Certificate Authorities
- **Dependencies**: `hyper-rustls`, `rustls-pemfile`
- **Enables**: `with_root_ca_pem()`, `with_root_ca_file()`, `with_pinned_cert_sha256()`

### `insecure-dangerous`

- **Default**: ❌ Disabled
- **Security**: ❌ **EXTREMELY DANGEROUS**
- **Use Case**: **Development/testing ONLY**
- **Warning**: **NEVER enable in production**
- **Enables**: `insecure_accept_invalid_certs()`, `with_self_signed_certs()`

## WebAssembly (WASM) Support

This crate supports WebAssembly targets with important security considerations:

```rust
// WASM builds will compile, but certain operations are restricted
#[cfg(target_arch = "wasm32")]
{
    let client = HttpClient::new(); // ✅ Works
    // Custom CA operations may return WasmNotImplemented errors
}
```

**WASM Limitations:**
- Custom Root CA installation requires browser/OS-level certificate management
- Some TLS configuration options may not be available
- Certificate pinning may be limited by browser security policies

**Browser Certificate Installation:**
1. Download your organization's Root CA certificate
2. Install it in your browser's certificate store
3. Mark it as trusted for websites
4. Your WASM application will then trust endpoints signed by that CA

## Error Handling

```rust
use hyper_custom_cert::{HttpClient, ClientError};

match client.request("https://example.com").await {
    Ok(_) => println!("Request successful"),
    Err(ClientError::WasmNotImplemented) => {
        println!("This operation isn't supported in WASM");
    }
    Err(e) => {
        println!("Request failed: {}", e);
    }
}
```

## Security Best Practices

### Production Recommendations

1. **Use Default Mode**: Stick with `native-tls` for public endpoints
2. **Custom CA Only When Needed**: Only use `rustls` feature when connecting to private CAs
3. **Never Use `insecure-dangerous`**: This feature should never be enabled in production
4. **Keep Dependencies Updated**: Monitor for security advisories
5. **Certificate Pinning**: Consider pinning for high-security applications

### Development vs Production

```rust
// ✅ GOOD: Production configuration
#[cfg(not(debug_assertions))]
let client = HttpClient::new(); // Uses OS trust store

// ✅ GOOD: Development configuration  
#[cfg(debug_assertions)]
let client = HttpClient::builder()
    .insecure_accept_invalid_certs(true)  // Only in debug builds
    .build();
```

## Examples

See the `examples/` directory for complete working examples:

- `examples/self-signed-certs/` - Comprehensive examples for all modes
- Example of connecting to public endpoints (default mode)
- Example of using custom Root CA for private services
- Example of development mode with self-signed certificates

## Testing

```bash
# Test with default features
cargo test

# Test with rustls features
cargo test --features rustls

# Test with all features (for development)
cargo test --features rustls,insecure-dangerous

# Test WASM compatibility
cargo test --target wasm32-unknown-unknown
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass: `cargo test --all-features`
6. Submit a pull request

## License

This project is licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Security Policy

For security vulnerabilities, please see [SECURITY.md](SECURITY.md) for our responsible disclosure policy.

---

**Remember**: This library prioritizes security by default. The `insecure-dangerous` feature exists solely for development convenience and should never be used in production environments.