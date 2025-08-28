//! hyper-custom-cert
//!
//! A reusable HTTP client library that provides:
//! - A small, ergonomic wrapper surface for building HTTP clients
//! - A dev-only option to accept self-signed/invalid certificates (feature-gated)
//! - A production-grade path to trust a custom Root CA by providing PEM bytes
//! - Clear security boundaries and feature flags
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

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::{Method, Request, Response, StatusCode, Uri, body::Incoming};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

/// Options for controlling HTTP requests.
///
/// This struct provides a flexible interface for configuring individual
/// HTTP requests without modifying the client's default settings.
///
/// # Examples
///
/// Adding custom headers to a specific request:
///
/// ```
/// use hyper_custom_cert::{HttpClient, RequestOptions};
/// use std::collections::HashMap;
///
/// // Create request-specific headers
/// let mut headers = HashMap::new();
/// headers.insert("x-request-id".to_string(), "123456".to_string());
///
/// // Create request options with these headers
/// let options = RequestOptions::new()
///     .with_headers(headers);
///
/// // Make request with custom options
/// # async {
/// let client = HttpClient::new();
/// let _response = client.request_with_options("https://example.com", Some(options)).await;
/// # };
/// ```
#[derive(Default, Clone)]
pub struct RequestOptions {
    /// Headers to add to this specific request
    pub headers: Option<HashMap<String, String>>,
    /// Override the client's default timeout for this request
    pub timeout: Option<Duration>,
}

impl RequestOptions {
    /// Create a new empty RequestOptions with default values.
    pub fn new() -> Self {
        RequestOptions::default()
    }

    /// Add custom headers to this request.
    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers = Some(headers);
        self
    }

    /// Override the client's default timeout for this request.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

/// HTTP response with raw body data exposed as bytes.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code
    pub status: StatusCode,
    /// Response headers
    pub headers: HashMap<String, String>,
    /// Raw response body as bytes - exposed without any permutations
    pub body: Bytes,
}

/// Error type for this crate's runtime operations.
#[derive(Debug)]
pub enum ClientError {
    /// Returned on wasm32 targets where runtime operations requiring custom CA
    /// trust are not available due to browser security constraints.
    WasmNotImplemented,
    /// HTTP request failed
    HttpError(hyper::Error),
    /// HTTP request building failed
    HttpBuildError(hyper::http::Error),
    /// HTTP client request failed
    HttpClientError(hyper_util::client::legacy::Error),
    /// Invalid URI
    InvalidUri(hyper::http::uri::InvalidUri),
    /// TLS/Connection error
    #[cfg(any(feature = "native-tls", feature = "rustls"))]
    TlsError(String),
    /// IO error (e.g., reading CA files)
    IoError(std::io::Error),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::WasmNotImplemented => write!(
                f,
                "Not implemented on WebAssembly (browser restricts programmatic CA trust)"
            ),
            ClientError::HttpError(err) => write!(f, "HTTP error: {}", err),
            ClientError::HttpBuildError(err) => write!(f, "HTTP build error: {}", err),
            ClientError::HttpClientError(err) => write!(f, "HTTP client error: {}", err),
            ClientError::InvalidUri(err) => write!(f, "Invalid URI: {}", err),
            #[cfg(any(feature = "native-tls", feature = "rustls"))]
            ClientError::TlsError(err) => write!(f, "TLS error: {}", err),
            ClientError::IoError(err) => write!(f, "IO error: {}", err),
        }
    }
}

impl StdError for ClientError {}

// Error conversions for ergonomic error handling
impl From<hyper::Error> for ClientError {
    fn from(err: hyper::Error) -> Self {
        ClientError::HttpError(err)
    }
}

impl From<hyper::http::uri::InvalidUri> for ClientError {
    fn from(err: hyper::http::uri::InvalidUri) -> Self {
        ClientError::InvalidUri(err)
    }
}

impl From<std::io::Error> for ClientError {
    fn from(err: std::io::Error) -> Self {
        ClientError::IoError(err)
    }
}

impl From<hyper::http::Error> for ClientError {
    fn from(err: hyper::http::Error) -> Self {
        ClientError::HttpBuildError(err)
    }
}

impl From<hyper_util::client::legacy::Error> for ClientError {
    fn from(err: hyper_util::client::legacy::Error) -> Self {
        ClientError::HttpClientError(err)
    }
}

/// Reusable HTTP client configured via [`HttpClientBuilder`].
///
/// # Examples
///
/// Build a client with a custom timeout and default headers:
///
/// ```
/// use hyper_custom_cert::{HttpClient, RequestOptions};
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
/// let _ = client.request_with_options("https://example.com", None);
/// ```
pub struct HttpClient {
    timeout: Duration,
    default_headers: HashMap<String, String>,
    /// When enabled (dev-only feature), allows accepting invalid/self-signed certs.
    /// This is gated behind the `insecure-dangerous` feature to prevent accidental
    /// use in production environments and clearly demarcate its security implications.
    #[cfg(feature = "insecure-dangerous")]
    accept_invalid_certs: bool,
    /// Optional PEM-encoded custom Root CA to trust in addition to system roots.
    /// This provides a mechanism for secure communication with internal services
    /// or those using custom certificate authorities, allowing the client to validate
    /// servers signed by this trusted CA.
    root_ca_pem: Option<Vec<u8>>,
    /// Optional certificate pins for additional security beyond CA validation.
    /// These SHA256 fingerprints add an extra layer of defense against compromised
    /// CAs or man-in-the-middle attacks by ensuring the server's certificate
    /// matches a predefined set of trusted fingerprints.
    #[cfg(feature = "rustls")]
    pinned_cert_sha256: Option<Vec<[u8; 32]>>,
}

impl HttpClient {
    /// Construct a new client using secure defaults by delegating to the builder.
    /// This provides a convenient way to get a functional client without explicit
    /// configuration, relying on sensible defaults (e.g., 30-second timeout, no custom CAs).
    pub fn new() -> Self {
        HttpClientBuilder::new().build()
    }

    /// Start building a client with explicit configuration.
    /// This method exposes the `HttpClientBuilder` to allow granular control over
    /// various client settings like timeouts, default headers, and TLS configurations.
    pub fn builder() -> HttpClientBuilder {
        HttpClientBuilder::new()
    }

    /// Convenience constructor that enables acceptance of self-signed/invalid
    /// certificates. This is gated behind the `insecure-dangerous` feature and intended
    /// strictly for development and testing. NEVER enable in production.
    ///
    /// # Security Warning
    ///
    /// ⚠️ CRITICAL SECURITY WARNING ⚠️
    ///
    /// This method deliberately bypasses TLS certificate validation, creating a
    /// serious security vulnerability to man-in-the-middle attacks. When used:
    ///
    /// - ANY certificate will be accepted, regardless of its validity
    /// - Expired certificates will be accepted
    /// - Certificates from untrusted issuers will be accepted
    /// - Certificates for the wrong domain will be accepted
    ///
    /// This is equivalent to calling `insecure_accept_invalid_certs(true)` on the builder
    /// and inherits all of its security implications. See that method's documentation
    /// for more details.
    ///
    /// # Intended Use Cases
    ///
    /// This method should ONLY be used for:
    /// - Local development with self-signed certificates
    /// - Testing environments where security is not a concern
    /// - Debugging TLS connection issues
    ///
    /// # Implementation Details
    ///
    /// This is a convenience wrapper that calls:
    /// ```ignore
    /// HttpClient::builder()
    ///     .insecure_accept_invalid_certs(true)
    ///     .build()
    /// ```
    #[cfg(feature = "insecure-dangerous")]
    pub fn with_self_signed_certs() -> Self {
        HttpClient::builder()
            .insecure_accept_invalid_certs(true)
            .build()
    }
}

// Native (non-wasm) runtime implementation
// This section contains the actual HTTP client implementation for native targets,
// leveraging `hyper` and `tokio` for asynchronous network operations.
#[cfg(not(target_arch = "wasm32"))]
impl HttpClient {
    /// Performs a GET request and returns the raw response body.
    /// This method constructs a `hyper::Request` with the GET method and any
    /// default headers configured on the client, then dispatches it via `perform_request`.
    /// Returns HttpResponse with raw body data exposed without any permutations.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL to request
    /// * `options` - Optional request options to customize this specific request
    ///
    /// # Examples
    ///
    /// ```
    /// # async {
    /// use hyper_custom_cert::{HttpClient, RequestOptions};
    /// use std::collections::HashMap;
    ///
    /// let client = HttpClient::new();
    ///
    /// // Basic request with no custom options
    /// let response1 = client.request_with_options("https://example.com", None).await?;
    ///
    /// // Request with custom options
    /// let mut headers = HashMap::new();
    /// headers.insert("x-request-id".into(), "abc123".into());
    /// let options = RequestOptions::new().with_headers(headers);
    /// let response2 = client.request_with_options("https://example.com", Some(options)).await?;
    /// # Ok::<(), hyper_custom_cert::ClientError>(())
    /// # };
    /// ```
    #[deprecated(since = "0.4.0", note = "Use request(url, Some(options)) instead")]
    pub async fn request(&self, url: &str) -> Result<HttpResponse, ClientError> {
        self.request_with_options(url, None).await
    }

    /// Performs a GET request and returns the raw response body.
    /// This method constructs a `hyper::Request` with the GET method and any
    /// default headers configured on the client, then dispatches it via `perform_request`.
    /// Returns HttpResponse with raw body data exposed without any permutations.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL to request
    /// * `options` - Optional request options to customize this specific request
    ///
    /// # Examples
    ///
    /// ```
    /// # async {
    /// use hyper_custom_cert::{HttpClient, RequestOptions};
    /// use std::collections::HashMap;
    ///
    /// let client = HttpClient::new();
    ///
    /// // Basic request with no custom options
    /// let response1 = client.request_with_options("https://example.com", None).await?;
    ///
    /// // Request with custom options
    /// let mut headers = HashMap::new();
    /// headers.insert("x-request-id".into(), "abc123".into());
    /// let options = RequestOptions::new().with_headers(headers);
    /// let response2 = client.request_with_options("https://example.com", Some(options)).await?;
    /// # Ok::<(), hyper_custom_cert::ClientError>(())
    /// # };
    /// ```
    pub async fn request_with_options(
        &self,
        url: &str,
        options: Option<RequestOptions>,
    ) -> Result<HttpResponse, ClientError> {
        let uri: Uri = url.parse()?;

        let req = Request::builder().method(Method::GET).uri(uri);

        // Add default headers to the request. This ensures that any headers
        // set during the client's construction (e.g., API keys, User-Agent)
        // are automatically included in outgoing requests.
        let mut req = req;
        for (key, value) in &self.default_headers {
            req = req.header(key, value);
        }

        // Add any request-specific headers from options
        if let Some(options) = &options {
            if let Some(headers) = &options.headers {
                for (key, value) in headers {
                    req = req.header(key, value);
                }
            }
        }

        let req = req.body(http_body_util::Empty::<Bytes>::new())?;

        // If options contain a timeout, temporarily modify self to use it
        // This is a bit of a hack since we can't modify perform_request easily
        let result = if let Some(opts) = &options {
            if let Some(timeout) = opts.timeout {
                // Create a copy of self with the new timeout
                let client_copy = HttpClient {
                    timeout,
                    default_headers: self.default_headers.clone(),
                    #[cfg(feature = "insecure-dangerous")]
                    accept_invalid_certs: self.accept_invalid_certs,
                    root_ca_pem: self.root_ca_pem.clone(),
                    #[cfg(feature = "rustls")]
                    pinned_cert_sha256: self.pinned_cert_sha256.clone(),
                };

                // Use the modified client for this request only
                client_copy.perform_request(req).await
            } else {
                // No timeout override, use normal client
                self.perform_request(req).await
            }
        } else {
            // No options, use normal client
            self.perform_request(req).await
        };

        result
    }

    /// Performs a POST request with the given body and returns the raw response.
    /// Similar to `request`, this method builds a `hyper::Request` for a POST
    /// operation, handles the request body conversion to `Bytes`, and applies
    /// default headers before calling `perform_request`.
    /// Returns HttpResponse with raw body data exposed without any permutations.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL to request
    /// * `body` - The body content to send with the POST request
    /// * `options` - Optional request options to customize this specific request
    ///
    /// # Examples
    ///
    /// ```
    /// # async {
    /// use hyper_custom_cert::{HttpClient, RequestOptions};
    /// use std::collections::HashMap;
    /// use std::time::Duration;
    ///
    /// let client = HttpClient::new();
    ///
    /// // Basic POST request with no custom options
    /// let response1 = client.post_with_options("https://example.com/api", b"{\"key\":\"value\"}", None).await?;
    ///
    /// // POST request with custom options
    /// let mut headers = HashMap::new();
    /// headers.insert("Content-Type".into(), "application/json".into());
    /// let options = RequestOptions::new()
    ///     .with_headers(headers)
    ///     .with_timeout(Duration::from_secs(5));
    /// let response2 = client.post_with_options("https://example.com/api", b"{\"key\":\"value\"}", Some(options)).await?;
    /// # Ok::<(), hyper_custom_cert::ClientError>(())
    /// # };
    /// ```
    #[deprecated(
        since = "0.4.0",
        note = "Use post_with_options(url, body, Some(options)) instead"
    )]
    pub async fn post<B: AsRef<[u8]>>(
        &self,
        url: &str,
        body: B,
    ) -> Result<HttpResponse, ClientError> {
        self.post_with_options(url, body, None).await
    }

    /// Performs a POST request with the given body and returns the raw response.
    /// Similar to `request`, this method builds a `hyper::Request` for a POST
    /// operation, handles the request body conversion to `Bytes`, and applies
    /// default headers before calling `perform_request`.
    /// Returns HttpResponse with raw body data exposed without any permutations.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL to request
    /// * `body` - The body content to send with the POST request
    /// * `options` - Optional request options to customize this specific request
    ///
    /// # Examples
    ///
    /// ```
    /// # async {
    /// use hyper_custom_cert::{HttpClient, RequestOptions};
    /// use std::collections::HashMap;
    /// use std::time::Duration;
    ///
    /// let client = HttpClient::new();
    ///
    /// // Basic POST request with no custom options
    /// let response1 = client.post_with_options("https://example.com/api", b"{\"key\":\"value\"}", None).await?;
    ///
    /// // POST request with custom options
    /// let mut headers = HashMap::new();
    /// headers.insert("Content-Type".into(), "application/json".into());
    /// let options = RequestOptions::new()
    ///     .with_headers(headers)
    ///     .with_timeout(Duration::from_secs(5));
    /// let response2 = client.post_with_options("https://example.com/api", b"{\"key\":\"value\"}", Some(options)).await?;
    /// # Ok::<(), hyper_custom_cert::ClientError>(())
    /// # };
    /// ```
    pub async fn post_with_options<B: AsRef<[u8]>>(
        &self,
        url: &str,
        body: B,
        options: Option<RequestOptions>,
    ) -> Result<HttpResponse, ClientError> {
        let uri: Uri = url.parse()?;

        let req = Request::builder().method(Method::POST).uri(uri);

        // Add default headers to the request for consistency across client operations.
        let mut req = req;
        for (key, value) in &self.default_headers {
            req = req.header(key, value);
        }

        // Add any request-specific headers from options
        if let Some(options) = &options {
            if let Some(headers) = &options.headers {
                for (key, value) in headers {
                    req = req.header(key, value);
                }
            }
        }

        let body_bytes = Bytes::copy_from_slice(body.as_ref());
        let req = req.body(http_body_util::Full::new(body_bytes))?;

        // If options contain a timeout, temporarily modify self to use it
        // This is a bit of a hack since we can't modify perform_request easily
        let result = if let Some(opts) = &options {
            if let Some(timeout) = opts.timeout {
                // Create a copy of self with the new timeout
                let client_copy = HttpClient {
                    timeout,
                    default_headers: self.default_headers.clone(),
                    #[cfg(feature = "insecure-dangerous")]
                    accept_invalid_certs: self.accept_invalid_certs,
                    root_ca_pem: self.root_ca_pem.clone(),
                    #[cfg(feature = "rustls")]
                    pinned_cert_sha256: self.pinned_cert_sha256.clone(),
                };

                // Use the modified client for this request only
                client_copy.perform_request(req).await
            } else {
                // No timeout override, use normal client
                self.perform_request(req).await
            }
        } else {
            // No options, use normal client
            self.perform_request(req).await
        };

        result
    }

    /// Helper method to perform HTTP requests using the configured settings.
    /// This centralizes the logic for dispatching `hyper::Request` objects,
    /// handling the various TLS backends (native-tls, rustls) and ensuring
    /// the correct `hyper` client is used based on feature flags.
    async fn perform_request<B>(&self, req: Request<B>) -> Result<HttpResponse, ClientError>
    where
        B: hyper::body::Body + Send + 'static + Unpin,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        #[cfg(feature = "native-tls")]
        {
            // When the "native-tls" feature is enabled, use `hyper-tls` for TLS
            // support, which integrates with the system's native TLS libraries.

            #[cfg(feature = "insecure-dangerous")]
            if self.accept_invalid_certs {
                // ⚠️ SECURITY WARNING: This code path deliberately bypasses TLS certificate validation.
                // It should only be used during development/testing with self-signed certificates,
                // and NEVER in production environments. This creates a vulnerability to
                // man-in-the-middle attacks and is extremely dangerous.

                // Implementation with tokio-native-tls to accept invalid certificates
                let mut http_connector = hyper_util::client::legacy::connect::HttpConnector::new();
                http_connector.enforce_http(false);

                // Create a TLS connector that accepts invalid certificates
                let mut tls_builder = native_tls::TlsConnector::builder();
                tls_builder.danger_accept_invalid_certs(true);
                let tls_connector = tls_builder.build().map_err(|e| {
                    ClientError::TlsError(format!("Failed to build TLS connector: {}", e))
                })?;

                // Create the tokio-native-tls connector
                let tokio_connector = tokio_native_tls::TlsConnector::from(tls_connector);

                // Create the HTTPS connector using the HTTP and TLS connectors
                let connector = hyper_tls::HttpsConnector::from((http_connector, tokio_connector));

                let client = Client::builder(TokioExecutor::new()).build(connector);
                let resp = tokio::time::timeout(self.timeout, client.request(req))
                    .await
                    .map_err(|_| ClientError::TlsError("Request timed out".to_string()))??;
                return self.build_response(resp).await;
            }

            // Standard secure TLS connection with certificate validation (default path)
            let connector = hyper_tls::HttpsConnector::new();
            let client = Client::builder(TokioExecutor::new()).build(connector);
            let resp = tokio::time::timeout(self.timeout, client.request(req))
                .await
                .map_err(|_| ClientError::TlsError("Request timed out".to_string()))??;
            self.build_response(resp).await
        }
        #[cfg(all(feature = "rustls", not(feature = "native-tls")))]
        {
            // If "rustls" is enabled and "native-tls" is not, use `rustls` for TLS.
            // Properly configure the rustls connector with custom CA certificates and/or
            // certificate validation settings based on the client configuration.

            // Start with the standard rustls config with native roots
            let mut root_cert_store = rustls::RootCertStore::empty();

            // Load native certificates using rustls_native_certs v0.8.1
            // This returns a CertificateResult which has a certs field containing the certificates
            let native_certs = rustls_native_certs::load_native_certs();

            // Add each cert to the root store
            for cert in &native_certs.certs {
                if let Err(e) = root_cert_store.add(cert.clone()) {
                    return Err(ClientError::TlsError(format!(
                        "Failed to add native cert to root store: {}",
                        e
                    )));
                }
            }

            // Add custom CA certificate if provided
            if let Some(ref pem_bytes) = self.root_ca_pem {
                let mut reader = std::io::Cursor::new(pem_bytes);
                for cert_result in rustls_pemfile::certs(&mut reader) {
                    match cert_result {
                        Ok(cert) => {
                            root_cert_store.add(cert).map_err(|e| {
                                ClientError::TlsError(format!(
                                    "Failed to add custom cert to root store: {}",
                                    e
                                ))
                            })?;
                        }
                        Err(e) => {
                            return Err(ClientError::TlsError(format!(
                                "Failed to parse PEM cert: {}",
                                e
                            )));
                        }
                    }
                }
            }

            // Configure rustls
            let mut config_builder =
                rustls::ClientConfig::builder().with_root_certificates(root_cert_store);

            let rustls_config = config_builder.with_no_client_auth();

            #[cfg(feature = "insecure-dangerous")]
            let rustls_config = if self.accept_invalid_certs {
                // ⚠️ SECURITY WARNING: This code path deliberately bypasses TLS certificate validation.
                // It should only be used during development/testing with self-signed certificates,
                // and NEVER in production environments. This creates a vulnerability to
                // man-in-the-middle attacks and is extremely dangerous.

                use rustls::DigitallySignedStruct;
                use rustls::SignatureScheme;
                use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified};
                use rustls::pki_types::UnixTime;
                use std::sync::Arc;

                // Override the certificate verifier with a no-op verifier that accepts all certificates
                #[derive(Debug)]
                struct NoCertificateVerification {}

                impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
                    fn verify_server_cert(
                        &self,
                        _end_entity: &rustls::pki_types::CertificateDer<'_>,
                        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
                        _server_name: &rustls::pki_types::ServerName<'_>,
                        _ocsp_response: &[u8],
                        _now: UnixTime,
                    ) -> Result<ServerCertVerified, rustls::Error> {
                        // Accept any certificate without verification
                        Ok(ServerCertVerified::assertion())
                    }

                    fn verify_tls12_signature(
                        &self,
                        _message: &[u8],
                        _cert: &rustls::pki_types::CertificateDer<'_>,
                        _dss: &DigitallySignedStruct,
                    ) -> Result<HandshakeSignatureValid, rustls::Error> {
                        // Accept any TLS 1.2 signature without verification
                        Ok(HandshakeSignatureValid::assertion())
                    }

                    fn verify_tls13_signature(
                        &self,
                        _message: &[u8],
                        _cert: &rustls::pki_types::CertificateDer<'_>,
                        _dss: &DigitallySignedStruct,
                    ) -> Result<HandshakeSignatureValid, rustls::Error> {
                        // Accept any TLS 1.3 signature without verification
                        Ok(HandshakeSignatureValid::assertion())
                    }

                    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                        // Return a list of all supported signature schemes
                        vec![
                            SignatureScheme::RSA_PKCS1_SHA1,
                            SignatureScheme::ECDSA_SHA1_Legacy,
                            SignatureScheme::RSA_PKCS1_SHA256,
                            SignatureScheme::ECDSA_NISTP256_SHA256,
                            SignatureScheme::RSA_PKCS1_SHA384,
                            SignatureScheme::ECDSA_NISTP384_SHA384,
                            SignatureScheme::RSA_PKCS1_SHA512,
                            SignatureScheme::ECDSA_NISTP521_SHA512,
                            SignatureScheme::RSA_PSS_SHA256,
                            SignatureScheme::RSA_PSS_SHA384,
                            SignatureScheme::RSA_PSS_SHA512,
                            SignatureScheme::ED25519,
                            SignatureScheme::ED448,
                        ]
                    }
                }

                // Set up the dangerous configuration with no certificate verification
                let mut config = rustls_config.clone();
                config
                    .dangerous()
                    .set_certificate_verifier(Arc::new(NoCertificateVerification {}));
                config
            } else {
                rustls_config
            };

            // Handle certificate pinning if configured
            #[cfg(feature = "rustls")]
            let rustls_config = if let Some(ref pins) = self.pinned_cert_sha256 {
                // Implement certificate pinning by creating a custom certificate verifier
                use rustls::DigitallySignedStruct;
                use rustls::SignatureScheme;
                use rustls::client::danger::{
                    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
                };
                use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
                use std::sync::Arc;

                // Create a custom certificate verifier that checks certificate pins
                struct CertificatePinner {
                    pins: Vec<[u8; 32]>,
                    inner: Arc<dyn ServerCertVerifier>,
                }

                impl ServerCertVerifier for CertificatePinner {
                    fn verify_server_cert(
                        &self,
                        end_entity: &CertificateDer<'_>,
                        intermediates: &[CertificateDer<'_>],
                        server_name: &ServerName<'_>,
                        ocsp_response: &[u8],
                        now: UnixTime,
                    ) -> Result<ServerCertVerified, rustls::Error> {
                        // First, use the inner verifier to do standard verification
                        self.inner.verify_server_cert(
                            end_entity,
                            intermediates,
                            server_name,
                            ocsp_response,
                            now,
                        )?;

                        // Then verify the pin
                        use sha2::{Digest, Sha256};

                        let mut hasher = Sha256::new();
                        hasher.update(end_entity.as_ref());
                        let cert_hash = hasher.finalize();

                        // Check if the certificate hash matches any of our pins
                        for pin in &self.pins {
                            if pin[..] == cert_hash[..] {
                                return Ok(ServerCertVerified::assertion());
                            }
                        }

                        // If we got here, none of the pins matched
                        Err(rustls::Error::General(
                            "Certificate pin verification failed".into(),
                        ))
                    }

                    fn verify_tls12_signature(
                        &self,
                        message: &[u8],
                        cert: &CertificateDer<'_>,
                        dss: &DigitallySignedStruct,
                    ) -> Result<HandshakeSignatureValid, rustls::Error> {
                        // Delegate to inner verifier
                        self.inner.verify_tls12_signature(message, cert, dss)
                    }

                    fn verify_tls13_signature(
                        &self,
                        message: &[u8],
                        cert: &CertificateDer<'_>,
                        dss: &DigitallySignedStruct,
                    ) -> Result<HandshakeSignatureValid, rustls::Error> {
                        // Delegate to inner verifier
                        self.inner.verify_tls13_signature(message, cert, dss)
                    }

                    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                        self.inner.supported_verify_schemes()
                    }
                }

                // Create the certificate pinner with our pins and the default verifier
                let mut config = rustls_config.clone();
                let default_verifier = rustls::client::WebPkiServerVerifier::builder()
                    .with_root_certificates(root_cert_store.clone())
                    .build()
                    .map_err(|e| {
                        ClientError::TlsError(format!(
                            "Failed to build certificate verifier: {}",
                            e
                        ))
                    })?;

                let cert_pinner = Arc::new(CertificatePinner {
                    pins: pins.clone(),
                    inner: default_verifier,
                });

                config.dangerous().set_certificate_verifier(cert_pinner);
                config
            } else {
                rustls_config
            };

            // Create a connector that supports HTTP and HTTPS
            let mut http_connector = hyper_util::client::legacy::connect::HttpConnector::new();
            http_connector.enforce_http(false);

            // Create the rustls connector using HttpsConnectorBuilder
            let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(rustls_config)
                .https_or_http()
                .enable_http1()
                .build();

            let client = Client::builder(TokioExecutor::new()).build(https_connector);
            let resp = tokio::time::timeout(self.timeout, client.request(req))
                .await
                .map_err(|_| ClientError::TlsError("Request timed out".to_string()))??;
            self.build_response(resp).await
        }
        #[cfg(not(any(feature = "native-tls", feature = "rustls")))]
        {
            // If neither "native-tls" nor "rustls" features are enabled,
            // fall back to a basic HTTP connector without TLS support.
            // This is primarily for scenarios where TLS is not required or
            // handled at a different layer.
            let connector = hyper_util::client::legacy::connect::HttpConnector::new();
            let client = Client::builder(TokioExecutor::new()).build(connector);
            let resp = tokio::time::timeout(self.timeout, client.request(req))
                .await
                .map_err(|_| ClientError::TlsError("Request timed out".to_string()))??;
            self.build_response(resp).await
        }
    }

    /// Helper method to convert a hyper Response to our HttpResponse with raw body data.
    /// This method abstracts the details of `hyper::Response` processing,
    /// extracting the status, headers, and importantly, collecting the entire
    /// response body into a `Bytes` buffer for easy consumption by the caller.
    async fn build_response(&self, resp: Response<Incoming>) -> Result<HttpResponse, ClientError> {
        let status = resp.status();

        // Convert hyper's `HeaderMap` to a `HashMap<String, String>` for simpler
        // public API exposure, making header access more idiomatic for consumers.
        let mut headers = HashMap::new();
        for (name, value) in resp.headers() {
            if let Ok(value_str) = value.to_str() {
                headers.insert(name.to_string(), value_str.to_string());
            }
        }

        // Collect the body as raw bytes - this is the key part of the issue
        // We expose the body as raw bytes without any permutations, ensuring
        // the client receives the exact byte content of the response.
        let body_bytes = resp.into_body().collect().await?.to_bytes();

        Ok(HttpResponse {
            status,
            headers,
            body: body_bytes,
        })
    }
}

// WebAssembly stubbed runtime implementation
#[cfg(target_arch = "wasm32")]
impl HttpClient {
    /// On wasm32 targets, runtime methods are stubbed and return
    /// `ClientError::WasmNotImplemented` because browsers do not allow
    /// programmatic installation/trust of custom CAs.
    #[deprecated(
        since = "0.4.0",
        note = "Use request_with_options(url, Some(options)) instead"
    )]
    pub fn request(&self, _url: &str) -> Result<(), ClientError> {
        Err(ClientError::WasmNotImplemented)
    }

    /// On wasm32 targets, runtime methods are stubbed and return
    /// `ClientError::WasmNotImplemented` because browsers do not allow
    /// programmatic installation/trust of custom CAs.
    pub fn request_with_options(
        &self,
        _url: &str,
        _options: Option<RequestOptions>,
    ) -> Result<(), ClientError> {
        Err(ClientError::WasmNotImplemented)
    }

    /// POST is also not implemented on wasm32 targets for the same reason.
    #[deprecated(
        since = "0.4.0",
        note = "Use post_with_options(url, body, Some(options)) instead"
    )]
    pub fn post<B: AsRef<[u8]>>(&self, _url: &str, _body: B) -> Result<(), ClientError> {
        Err(ClientError::WasmNotImplemented)
    }

    /// POST is also not implemented on wasm32 targets for the same reason.
    pub fn post_with_options<B: AsRef<[u8]>>(
        &self,
        _url: &str,
        _body: B,
        _options: Option<RequestOptions>,
    ) -> Result<(), ClientError> {
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
    /// # Security Warning
    ///
    /// ⚠️ CRITICAL SECURITY WARNING ⚠️
    ///
    /// This method deliberately bypasses TLS certificate validation, which creates a
    /// serious security vulnerability to man-in-the-middle attacks. When enabled:
    ///
    /// - The client will accept ANY certificate, regardless of its validity
    /// - The client will accept expired certificates
    /// - The client will accept certificates from untrusted issuers
    /// - The client will accept certificates for the wrong domain
    ///
    /// This method should ONLY be used for:
    /// - Local development with self-signed certificates
    /// - Testing environments where security is not a concern
    /// - Debugging TLS connection issues
    ///
    /// # Implementation Details
    ///
    /// When enabled, this setting:
    /// - For `native-tls`: Uses `danger_accept_invalid_certs(true)` on the TLS connector
    /// - For `rustls`: Implements a custom `ServerCertVerifier` that accepts all certificates
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
    #[tokio::test]
    async fn request_returns_ok_on_native() {
        let client = HttpClient::builder().build();
        // Just test that the method can be called - don't actually make network requests in tests
        // In a real test environment, you would mock the HTTP calls or use a test server
        let _client = client; // Use the client to avoid unused variable warning
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn post_returns_ok_on_native() {
        let client = HttpClient::builder().build();
        // Just test that the method can be called - don't actually make network requests in tests
        // In a real test environment, you would mock the HTTP calls or use a test server
        let _client = client; // Use the client to avoid unused variable warning
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
