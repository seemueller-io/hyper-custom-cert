//! hyper-custom-cert
//!
//! A reusable HTTP client library that provides:
//! - A small, ergonomic wrapper surface for building HTTP clients
//! - A dev-only option to accept self-signed/invalid certificates (feature-gated)
//! - A production-grade path to trust a custom Root CA by providing PEM bytes
//! - Clear security boundaries and feature flags
//!
//! This crate is derived from a reference implementation located under
//! `reference-implementation/hyper-custom-cert` in this repository. The reference
//! implementation remains unchanged and serves as inspiration and verification.
//!
//! Note: Networking internals are intentionally abstracted for now; this crate
//! focuses on a robust and secure configuration API surfaced via a builder.
//!
//! WebAssembly support and limitations
//! -----------------------------------
//! For wasm32 targets, this crate currently exposes API stubs that return
//! `ClientError::WasmNotImplemented` when attempting to perform operations that
//! would require configuring a TLS client with a custom Root CA. This is by design:
//!
//! Browsers do not allow web applications to programmatically install or trust
//! custom Certificate Authorities. Trust decisions are enforced by the browser and
//! the underlying OS. As a result, while native builds can securely add a custom
//! Root CA (e.g., via `with_root_ca_pem` behind the `rustls` feature), the same is
//! not possible in the browser environment. Any runtime method that would require
//! such behavior will return `WasmNotImplemented` on wasm targets.
//!
//! If you need to target WebAssembly, build with `--no-default-features` to avoid
//! pulling in native TLS dependencies, and expect stubbed behavior until a future
//! browser capability or design change enables safe support.

use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;
#[cfg(feature = "rustls")]
use std::fs;
#[cfg(feature = "rustls")]
use std::path::Path;
use std::time::Duration;

/// Error type for this crate's runtime operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// Returned on wasm32 targets where runtime operations requiring custom CA
    /// trust are not available due to browser security constraints.
    WasmNotImplemented,
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::WasmNotImplemented => write!(
                f,
                "Not implemented on WebAssembly (browser restricts programmatic CA trust)"
            ),
        }
    }
}

impl StdError for ClientError {}

/// Reusable HTTP client configured via [`HttpClientBuilder`].
///
/// # Examples
///
/// Build a client with a custom timeout and default headers:
///
/// ```
/// use hyper_custom_cert::HttpClient;
/// use std::time::Duration;
/// use std::collections::HashMap;
///
/// let mut headers = HashMap::new();
/// headers.insert("x-app".into(), "demo".into());
///
/// let client = HttpClient::builder()
///     .with_timeout(Duration::from_secs(10))
///     .with_default_headers(headers)
///     .build();
///
/// // Placeholder call; does not perform I/O in this crate.
/// let _ = client.request("https://example.com");
/// ```
pub struct HttpClient {
    timeout: Duration,
    default_headers: HashMap<String, String>,
    /// When enabled (dev-only feature), allows accepting invalid/self-signed certs.
    #[cfg(feature = "insecure-dangerous")]
    accept_invalid_certs: bool,
    /// Optional PEM-encoded custom Root CA to trust in addition to system roots.
    root_ca_pem: Option<Vec<u8>>,
    /// Optional certificate pins for additional security beyond CA validation.
    #[cfg(feature = "rustls")]
    pinned_cert_sha256: Option<Vec<[u8; 32]>>,
}

impl HttpClient {
    /// Construct a new client using secure defaults by delegating to the builder.
    pub fn new() -> Self {
        HttpClientBuilder::new().build()
    }

    /// Start building a client with explicit configuration.
    pub fn builder() -> HttpClientBuilder {
        HttpClientBuilder::new()
    }

    /// Convenience constructor that enables acceptance of self-signed/invalid
    /// certificates. This is gated behind the `insecure-dangerous` feature and intended
    /// strictly for development and testing. NEVER enable in production.
    #[cfg(feature = "insecure-dangerous")]
    pub fn with_self_signed_certs() -> Self {
        HttpClient::builder()
            .insecure_accept_invalid_certs(true)
            .build()
    }
}

// Native (non-wasm) runtime placeholder implementation
#[cfg(not(target_arch = "wasm32"))]
impl HttpClient {
    /// Minimal runtime method to demonstrate how requests would be issued.
    /// On native targets, this currently returns Ok(()) as a placeholder
    /// without performing network I/O.
    pub fn request(&self, _url: &str) -> Result<(), ClientError> {
        // Touch configuration fields to avoid dead_code warnings until
        // network I/O is implemented.
        let _ = (&self.timeout, &self.default_headers, &self.root_ca_pem);
        #[cfg(feature = "insecure-dangerous")]
        let _ = &self.accept_invalid_certs;
        #[cfg(feature = "rustls")]
        let _ = &self.pinned_cert_sha256;
        Ok(())
    }
}

// WebAssembly stubbed runtime implementation
#[cfg(target_arch = "wasm32")]
impl HttpClient {
    /// On wasm32 targets, runtime methods are stubbed and return
    /// `ClientError::WasmNotImplemented` because browsers do not allow
    /// programmatic installation/trust of custom CAs.
    pub fn request(&self, _url: &str) -> Result<(), ClientError> {
        Err(ClientError::WasmNotImplemented)
    }
}

/// Builder for configuring and creating an [`HttpClient`].
pub struct HttpClientBuilder {
    timeout: Duration,
    default_headers: HashMap<String, String>,
    #[cfg(feature = "insecure-dangerous")]
    accept_invalid_certs: bool,
    root_ca_pem: Option<Vec<u8>>,
    #[cfg(feature = "rustls")]
    pinned_cert_sha256: Option<Vec<[u8; 32]>>,
}

impl HttpClientBuilder {
    /// Start a new builder with default settings.
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            default_headers: HashMap::new(),
            #[cfg(feature = "insecure-dangerous")]
            accept_invalid_certs: false,
            root_ca_pem: None,
            #[cfg(feature = "rustls")]
            pinned_cert_sha256: None,
        }
    }

    /// Set a request timeout to apply to client operations.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set default headers that will be added to every request initiated by this client.
    pub fn with_default_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.default_headers = headers;
        self
    }

    /// Dev-only: accept self-signed/invalid TLS certificates. Requires the
    /// `insecure-dangerous` feature to be enabled. NEVER enable this in production.
    ///
    /// # Examples
    ///
    /// Enable insecure mode during local development (dangerous):
    ///
    /// ```ignore
    /// use hyper_custom_cert::HttpClient;
    ///
    /// // Requires: --features insecure-dangerous
    /// let client = HttpClient::builder()
    ///     .insecure_accept_invalid_certs(true)
    ///     .build();
    /// ```
    #[cfg(feature = "insecure-dangerous")]
    pub fn insecure_accept_invalid_certs(mut self, accept: bool) -> Self {
        self.accept_invalid_certs = accept;
        self
    }

    /// Provide a PEM-encoded Root CA certificate to be trusted by the client.
    /// This is the production-ready way to trust a custom CA.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use hyper_custom_cert::HttpClient;
    ///
    /// // Requires: --no-default-features --features rustls
    /// let client = HttpClient::builder()
    ///     .with_root_ca_pem(include_bytes!("../examples-data/root-ca.pem"))
    ///     .build();
    /// ```
    #[cfg(feature = "rustls")]
    pub fn with_root_ca_pem(mut self, pem_bytes: &[u8]) -> Self {
        self.root_ca_pem = Some(pem_bytes.to_vec());
        self
    }

    /// Provide a PEM-encoded Root CA certificate file to be trusted by the client.
    /// This is the production-ready way to trust a custom CA from a file path.
    ///
    /// The file will be read during builder configuration and its contents stored
    /// in the client. This method will panic if the file cannot be read, similar
    /// to how `include_bytes!` macro behaves.
    ///
    /// # Security Considerations
    ///
    /// Only use certificate files from trusted sources. Ensure proper file permissions
    /// are set to prevent unauthorized modification of the certificate file.
    ///
    /// # Panics
    ///
    /// This method will panic if:
    /// - The file does not exist
    /// - The file cannot be read due to permissions or I/O errors
    /// - The path is invalid
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use hyper_custom_cert::HttpClient;
    ///
    /// // Requires: --no-default-features --features rustls
    /// let client = HttpClient::builder()
    ///     .with_root_ca_file("path/to/root-ca.pem")
    ///     .build();
    /// ```
    ///
    /// Using a `std::path::Path`:
    ///
    /// ```ignore
    /// use hyper_custom_cert::HttpClient;
    /// use std::path::Path;
    ///
    /// // Requires: --no-default-features --features rustls
    /// let ca_path = Path::new("certs/custom-ca.pem");
    /// let client = HttpClient::builder()
    ///     .with_root_ca_file(ca_path)
    ///     .build();
    /// ```
    #[cfg(feature = "rustls")]
    pub fn with_root_ca_file<P: AsRef<Path>>(mut self, path: P) -> Self {
        let pem_bytes = fs::read(path.as_ref()).unwrap_or_else(|e| {
            panic!(
                "Failed to read CA certificate file '{}': {}",
                path.as_ref().display(),
                e
            )
        });
        self.root_ca_pem = Some(pem_bytes);
        self
    }

    /// Configure certificate pinning using SHA256 fingerprints for additional security.
    ///
    /// Certificate pinning provides an additional layer of security beyond CA validation
    /// by verifying that the server's certificate matches one of the provided fingerprints.
    /// This helps protect against compromised CAs and man-in-the-middle attacks.
    ///
    /// # Security Considerations
    ///
    /// - Certificate pinning should be used in conjunction with, not as a replacement for,
    ///   proper CA validation.
    /// - Pinned certificates must be updated when the server's certificate changes.
    /// - Consider having backup pins for certificate rotation scenarios.
    /// - This method provides additional security but requires careful maintenance.
    ///
    /// # Parameters
    ///
    /// * `pins` - A vector of 32-byte SHA256 fingerprints of certificates to pin.
    ///   Each fingerprint should be the SHA256 hash of the certificate's DER encoding.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use hyper_custom_cert::HttpClient;
    ///
    /// // Example SHA256 fingerprints (these are just examples)
    /// let pin1: [u8; 32] = [
    ///     0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    ///     0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    ///     0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    ///     0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18
    /// ];
    ///
    /// let pin2: [u8; 32] = [
    ///     0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
    ///     0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
    ///     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    ///     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    /// ];
    ///
    /// // Requires: --no-default-features --features rustls
    /// let client = HttpClient::builder()
    ///     .with_pinned_cert_sha256(vec![pin1, pin2])
    ///     .build();
    /// ```
    #[cfg(feature = "rustls")]
    pub fn with_pinned_cert_sha256(mut self, pins: Vec<[u8; 32]>) -> Self {
        self.pinned_cert_sha256 = Some(pins);
        self
    }

    /// Finalize the configuration and build an [`HttpClient`].
    pub fn build(self) -> HttpClient {
        HttpClient {
            timeout: self.timeout,
            default_headers: self.default_headers,
            #[cfg(feature = "insecure-dangerous")]
            accept_invalid_certs: self.accept_invalid_certs,
            root_ca_pem: self.root_ca_pem,
            #[cfg(feature = "rustls")]
            pinned_cert_sha256: self.pinned_cert_sha256,
        }
    }
}

/// Default construction uses builder defaults.
impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Default builder state is secure and ergonomic.
impl Default for HttpClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_default_builds() {
        let _client = HttpClient::builder().build();
    }

    #[test]
    fn builder_allows_timeout_and_headers() {
        let mut headers = HashMap::new();
        headers.insert("x-test".into(), "1".into());
        let builder = HttpClient::builder()
            .with_timeout(Duration::from_secs(5))
            .with_default_headers(headers);
        #[cfg(feature = "rustls")]
        let builder = builder.with_root_ca_pem(b"-----BEGIN CERTIFICATE-----\n...");
        let _client = builder.build();
    }

    #[cfg(feature = "insecure-dangerous")]
    #[test]
    fn builder_allows_insecure_when_feature_enabled() {
        let _client = HttpClient::builder()
            .insecure_accept_invalid_certs(true)
            .build();
        let _client2 = HttpClient::with_self_signed_certs();
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn request_returns_ok_on_native() {
        let client = HttpClient::builder().build();
        let res = client.request("https://example.com");
        assert!(res.is_ok());
    }

    #[cfg(all(feature = "rustls", not(target_arch = "wasm32")))]
    #[test]
    fn builder_allows_root_ca_file() {
        use std::fs;
        use std::io::Write;

        // Create a temporary file with test certificate content
        let temp_dir = std::env::temp_dir();
        let cert_file = temp_dir.join("test-ca.pem");

        let test_cert = b"-----BEGIN CERTIFICATE-----
MIICxjCCAa4CAQAwDQYJKoZIhvcNAQELBQAwEjEQMA4GA1UEAwwHVGVzdCBDQTAe
Fw0yNTA4MTQwMDAwMDBaFw0yNjA4MTQwMDAwMDBaMBIxEDAOBgNVBAMMB1Rlc3Qg
Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDTest...
-----END CERTIFICATE-----";

        // Write test certificate to temporary file
        {
            let mut file = fs::File::create(&cert_file).expect("Failed to create temp cert file");
            file.write_all(test_cert)
                .expect("Failed to write cert to temp file");
        }

        // Test that the builder can read the certificate file
        let client = HttpClient::builder().with_root_ca_file(&cert_file).build();

        // Verify the certificate was loaded
        assert!(client.root_ca_pem.is_some());
        assert_eq!(client.root_ca_pem.as_ref().unwrap(), test_cert);

        // Clean up
        let _ = fs::remove_file(cert_file);
    }
}
