//! Integration tests for various feature combinations
//!
//! These tests verify that the library works correctly with different
//! combinations of features enabled/disabled, ensuring proper conditional
//! compilation and feature interactions.

use hyper_custom_cert::HttpClient;
#[cfg(any(
    all(feature = "rustls", feature = "insecure-dangerous"),
    all(feature = "native-tls", feature = "insecure-dangerous"),
    not(any(feature = "rustls", feature = "insecure-dangerous")),
    all(feature = "native-tls", feature = "rustls", feature = "insecure-dangerous")
))]
use std::collections::HashMap;
use std::time::Duration;

// Test CA certificate for combination tests
#[allow(dead_code)]
const TEST_CA_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKoK/heBjcOuMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTcwODI4MTUxMzAyWhcNMjcwODI2MTUxMzAyWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAuuExKtKjKEw91uR8gqyUZx+wW3qZjUHq3oLe+RxbEUVFWApwrKE3XxKJ
-----END CERTIFICATE-----";

// Test with rustls + insecure-dangerous features together
#[cfg(all(feature = "rustls", feature = "insecure-dangerous"))]
#[test]
fn rustls_and_insecure_combination() {
    // Test combining rustls custom CA with insecure certificate acceptance
    let _client = HttpClient::builder()
        .with_root_ca_pem(TEST_CA_PEM)
        .insecure_accept_invalid_certs(true)
        .build();

    // Test passes if compilation succeeds
}

#[cfg(all(feature = "rustls", feature = "insecure-dangerous"))]
#[test]
fn rustls_pinning_and_insecure_combination() {
    // Test combining certificate pinning with insecure mode (unusual but valid)
    let pins = vec![[
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08,
    ]];

    let _client = HttpClient::builder()
        .with_pinned_cert_sha256(pins)
        .insecure_accept_invalid_certs(true)
        .with_timeout(Duration::from_secs(30))
        .build();

    // Test passes if compilation succeeds
}

#[cfg(all(feature = "rustls", feature = "insecure-dangerous"))]
#[test]
fn full_rustls_insecure_configuration() {
    // Test using all rustls and insecure features together
    let mut headers = HashMap::new();
    headers.insert("X-Custom".to_string(), "test".to_string());

    let pins = vec![[0u8; 32]];

    let _client = HttpClient::builder()
        .with_timeout(Duration::from_secs(45))
        .with_default_headers(headers)
        .with_root_ca_pem(TEST_CA_PEM)
        .with_root_ca_pem(TEST_CA_PEM) // Second CA via PEM instead of file
        .with_pinned_cert_sha256(pins)
        .insecure_accept_invalid_certs(true)
        .build();

    // Test passes if compilation succeeds
}

// Test with native-tls + insecure-dangerous (default + insecure)
#[cfg(all(feature = "native-tls", feature = "insecure-dangerous"))]
#[test]
fn native_tls_and_insecure_combination() {
    // Test combining native-tls (default) with insecure mode
    let _client = HttpClient::builder()
        .with_timeout(Duration::from_secs(20))
        .insecure_accept_invalid_certs(true)
        .build();

    // Test passes if compilation succeeds
}

#[cfg(all(feature = "native-tls", feature = "insecure-dangerous"))]
#[test]
fn native_tls_insecure_with_headers() {
    // Test native-tls + insecure with custom headers
    let mut headers = HashMap::new();
    headers.insert("Authorization".to_string(), "Bearer test".to_string());
    headers.insert("Content-Type".to_string(), "application/json".to_string());

    let _client = HttpClient::builder()
        .with_default_headers(headers)
        .insecure_accept_invalid_certs(true)
        .build();

    // Test passes if compilation succeeds
}

// Test with no optional features (base functionality only)
#[cfg(not(any(feature = "rustls", feature = "insecure-dangerous")))]
#[test]
fn minimal_feature_set() {
    // Test with only the default native-tls feature
    let _client = HttpClient::builder()
        .with_timeout(Duration::from_secs(30))
        .build();

    // Test passes if compilation succeeds
}

#[cfg(not(any(feature = "rustls", feature = "insecure-dangerous")))]
#[test]
fn minimal_with_headers_only() {
    // Test minimal feature set with headers configuration
    let mut headers = HashMap::new();
    headers.insert("User-Agent".to_string(), "minimal-client".to_string());

    let _client = HttpClient::builder()
        .with_default_headers(headers)
        .with_timeout(Duration::from_millis(5000))
        .build();

    // Test passes if compilation succeeds
}

// Test with all features enabled
#[cfg(all(
    feature = "native-tls",
    feature = "rustls",
    feature = "insecure-dangerous"
))]
#[test]
fn all_features_enabled() {
    // Test when all features are available
    let mut headers = HashMap::new();
    headers.insert("X-All-Features".to_string(), "enabled".to_string());

    let pins = vec![[0x42; 32]];

    let _client = HttpClient::builder()
        .with_timeout(Duration::from_secs(60))
        .with_default_headers(headers)
        .with_root_ca_pem(TEST_CA_PEM)
        .with_pinned_cert_sha256(pins)
        .insecure_accept_invalid_certs(false) // Safe default even with insecure available
        .build();

    // Test passes if compilation succeeds
}

#[cfg(all(
    feature = "native-tls",
    feature = "rustls",
    feature = "insecure-dangerous"
))]
#[test]
fn all_features_insecure_enabled() {
    // Test all features with insecure mode actually enabled
    let _client = HttpClient::builder()
        .with_root_ca_pem(TEST_CA_PEM) // Use PEM instead of file for CI/CD compatibility
        .insecure_accept_invalid_certs(true)
        .build();

    // Test passes if compilation succeeds
}

// Test feature availability at compile time
#[test]
fn feature_availability_check() {
    // This test documents which features are available at compile time
    let _client = HttpClient::builder();

    // Always available (default)
    let _default_client = HttpClient::new();
    let _builder = HttpClient::builder().with_timeout(Duration::from_secs(10));

    #[cfg(feature = "rustls")]
    {
        // rustls features should be available
        let _rustls_client = HttpClient::builder().with_root_ca_pem(TEST_CA_PEM);
    }

    #[cfg(feature = "insecure-dangerous")]
    {
        // insecure features should be available
        let _insecure_client = HttpClient::builder().insecure_accept_invalid_certs(true);
    }

    // Test passes if compilation succeeds
}

// Test builder method chaining with different feature combinations
#[cfg(feature = "rustls")]
#[test]
fn rustls_method_chaining() {
    // Test method chaining with rustls features
    // Note: Using only PEM method to avoid file I/O in tests
    let _client = HttpClient::builder()
        .with_timeout(Duration::from_secs(30))
        .with_root_ca_pem(TEST_CA_PEM)
        .with_root_ca_pem(TEST_CA_PEM) // Chain multiple PEM calls instead of file
        .build();

    // Test passes if compilation succeeds
}

#[cfg(feature = "insecure-dangerous")]
#[test]
fn insecure_method_chaining() {
    // Test method chaining with insecure features
    let mut headers = HashMap::new();
    headers.insert("Test".to_string(), "chaining".to_string());

    let _client = HttpClient::builder()
        .with_timeout(Duration::from_millis(1000))
        .with_default_headers(headers)
        .insecure_accept_invalid_certs(true)
        .build();

    // Test passes if compilation succeeds
}

// Test error conditions with different feature combinations
#[test]
fn basic_error_handling() {
    // Test basic error handling regardless of features
    let _client = HttpClient::new();

    // This would test actual error scenarios in a real implementation
    // For now, just verify the client was created successfully
    // Test passes if compilation succeeds
}

#[cfg(all(feature = "rustls", feature = "insecure-dangerous"))]
#[test]
fn complex_configuration_order() {
    // Test that configuration order doesn't matter with multiple features
    let pins = vec![[1u8; 32], [2u8; 32]];
    let mut headers = HashMap::new();
    headers.insert("Order".to_string(), "test".to_string());

    // Configuration in one order
    let client1 = HttpClient::builder()
        .insecure_accept_invalid_certs(true)
        .with_root_ca_pem(TEST_CA_PEM)
        .with_pinned_cert_sha256(pins.clone())
        .with_timeout(Duration::from_secs(15))
        .with_default_headers(headers.clone())
        .build();

    // Configuration in different order
    let client2 = HttpClient::builder()
        .with_default_headers(headers)
        .with_timeout(Duration::from_secs(15))
        .with_pinned_cert_sha256(pins)
        .with_root_ca_pem(TEST_CA_PEM)
        .insecure_accept_invalid_certs(true)
        .build();

    // Test passes if compilation succeeds
}
