//! Integration tests for insecure-dangerous features
//!
//! These tests verify that the library works correctly with the insecure-dangerous
//! feature enabled. This feature should ONLY be used for development and testing.
//!
//! ⚠️ WARNING: The insecure-dangerous feature disables important security checks.
//! Never use this in production environments!

use hyper_custom_cert::HttpClient;

#[cfg(feature = "insecure-dangerous")]
#[test]
fn insecure_accept_invalid_certs_enabled() {
    // Test enabling insecure certificate acceptance (development only!)
    let _client = HttpClient::builder()
        .insecure_accept_invalid_certs(true)
        .build();

    // Test passes if compilation succeeds
}

#[cfg(feature = "insecure-dangerous")]
#[test]
fn insecure_accept_invalid_certs_disabled() {
    // Test explicitly disabling insecure certificate acceptance
    let _client = HttpClient::builder()
        .insecure_accept_invalid_certs(false)
        .build();

    // Test passes if compilation succeeds
}

#[cfg(feature = "insecure-dangerous")]
#[test]
fn insecure_with_timeout_configuration() {
    // Test insecure mode combined with timeout configuration
    let _client = HttpClient::builder()
        .with_timeout(Duration::from_secs(30))
        .insecure_accept_invalid_certs(true)
        .build();

    // Test passes if compilation succeeds
}

#[cfg(feature = "insecure-dangerous")]
#[test]
fn insecure_with_headers_configuration() {
    // Test insecure mode combined with custom headers
    let mut headers = HashMap::new();
    headers.insert("X-Test-Header".to_string(), "test-value".to_string());
    headers.insert("Accept".to_string(), "application/json".to_string());

    let _client = HttpClient::builder()
        .with_default_headers(headers)
        .insecure_accept_invalid_certs(true)
        .build();

    // Test passes if compilation succeeds
}

#[cfg(feature = "insecure-dangerous")]
#[test]
fn insecure_combined_configuration() {
    // Test insecure mode with multiple configuration options
    let mut headers = HashMap::new();
    headers.insert("User-Agent".to_string(), "test-insecure-client".to_string());

    let _client = HttpClient::builder()
        .with_timeout(Duration::from_secs(60))
        .with_default_headers(headers)
        .insecure_accept_invalid_certs(true)
        .build();

    // Test passes if compilation succeeds
}

#[cfg(all(feature = "insecure-dangerous", feature = "rustls"))]
#[test]
fn insecure_with_rustls_ca_configuration() {
    // Test insecure mode combined with custom CA (when both features are enabled)
    const TEST_CA_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKoK/heBjcOuMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTcwODI4MTUxMzAyWhcNMjcwODI2MTUxMzAyWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAuuExKtKjKEw91uR8gqyUZx+wW3qZjUHq3oLe+RxbEUVFWApwrKE3XxKJ
-----END CERTIFICATE-----";

    let _client = HttpClient::builder()
        .with_root_ca_pem(TEST_CA_PEM)
        .insecure_accept_invalid_certs(true)
        .build();

    // Test passes if compilation succeeds
}

#[cfg(all(feature = "insecure-dangerous", feature = "rustls"))]
#[test]
fn insecure_with_certificate_pinning() {
    // Test insecure mode with certificate pinning (unusual but possible combination)
    let pins = vec![[0u8; 32]]; // Test pin

    let _client = HttpClient::builder()
        .with_pinned_cert_sha256(pins)
        .insecure_accept_invalid_certs(true)
        .build();

    // Test passes if compilation succeeds
}

#[cfg(feature = "insecure-dangerous")]
#[test]
fn insecure_static_convenience_method() {
    // Test the static convenience method for self-signed certs
    let _client = HttpClient::with_self_signed_certs();

    // Test passes if compilation succeeds
}

#[cfg(feature = "insecure-dangerous")]
#[test]
fn insecure_multiple_configurations() {
    // Test creating multiple clients with different insecure settings
    let client1 = HttpClient::builder()
        .insecure_accept_invalid_certs(true)
        .build();

    let client2 = HttpClient::builder()
        .insecure_accept_invalid_certs(false)
        .build();

    let client3 = HttpClient::builder()
        .with_timeout(Duration::from_secs(10))
        .insecure_accept_invalid_certs(true)
        .build();

    // Test passes if compilation succeeds
}

// Test that runs only when insecure-dangerous feature is NOT enabled
#[cfg(not(feature = "insecure-dangerous"))]
#[test]
fn insecure_methods_not_available_without_feature() {
    // This test should only compile and run when insecure-dangerous feature is disabled
    let _builder = HttpClient::builder();

    // The following would cause compilation errors if insecure-dangerous feature is not enabled:
    // builder.insecure_accept_invalid_certs(true);

    // The static method should also not be available:
    // let _client = HttpClient::with_self_signed_certs();

    // Test passes if compilation succeeds
}

#[cfg(not(feature = "insecure-dangerous"))]
#[test]
fn insecure_static_method_not_available() {
    // Verify that the static convenience method is not available without the feature
    // HttpClient::with_self_signed_certs(); // This should cause a compilation error

    // Instead, we can only use the safe default methods
    let _client = HttpClient::new();
    let _client2 = HttpClient::default();

    // Test passes if compilation succeeds
}

// Documentation test to ensure proper feature gating
#[cfg(feature = "insecure-dangerous")]
#[test]
fn insecure_feature_documentation_reminder() {
    // This test serves as a documentation reminder about the dangers of this feature

    // ⚠️ CRITICAL SECURITY WARNING ⚠️
    // The insecure-dangerous feature should NEVER be used in production!
    // It disables certificate validation and makes connections vulnerable to
    // man-in-the-middle attacks.

    // This feature is only intended for:
    // - Local development with self-signed certificates
    // - Testing environments where security is not a concern
    // - Debugging TLS connection issues

    let _client = HttpClient::builder()
        .insecure_accept_invalid_certs(true)
        .build();

    // Test passes if compilation succeeds
}
