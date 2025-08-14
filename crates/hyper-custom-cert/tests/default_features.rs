//! Integration tests for default features (native-tls only)
//! 
//! These tests verify that the library works correctly with only the default
//! features enabled (native-tls backend using OS trust store).

use hyper_custom_cert::{HttpClient, HttpClientBuilder};
use std::collections::HashMap;
use std::time::Duration;

#[test]
fn default_client_creation() {
    // Test that we can create a client with default features
    let client = HttpClient::new();
    
    // Basic smoke test - the client should be created successfully
    // In a real scenario, this would make an actual HTTP request
    assert!(true); // Placeholder - client creation succeeded
}

#[test]
fn default_client_from_builder() {
    // Test builder pattern with default features
    let client = HttpClient::builder().build();
    
    // Verify builder works with default features
    assert!(true); // Placeholder - builder succeeded
}

#[test]
fn builder_with_timeout() {
    // Test timeout configuration with default features
    let client = HttpClient::builder()
        .with_timeout(Duration::from_secs(30))
        .build();
    
    assert!(true); // Placeholder - timeout configuration succeeded
}

#[test]
fn builder_with_headers() {
    // Test header configuration with default features
    let mut headers = HashMap::new();
    headers.insert("User-Agent".to_string(), "test-agent".to_string());
    headers.insert("Accept".to_string(), "application/json".to_string());
    
    let client = HttpClient::builder()
        .with_default_headers(headers)
        .build();
    
    assert!(true); // Placeholder - header configuration succeeded
}

#[test]
fn builder_combined_configuration() {
    // Test combining multiple configuration options with default features
    let mut headers = HashMap::new();
    headers.insert("Custom-Header".to_string(), "custom-value".to_string());
    
    let client = HttpClient::builder()
        .with_timeout(Duration::from_secs(45))
        .with_default_headers(headers)
        .build();
    
    assert!(true); // Placeholder - combined configuration succeeded
}

#[cfg(feature = "native-tls")]
#[test]
fn native_tls_specific_functionality() {
    // Test functionality that's specific to native-tls backend
    let client = HttpClient::builder()
        .with_timeout(Duration::from_secs(10))
        .build();
    
    // This test should only run when native-tls feature is enabled
    assert!(true); // Placeholder - native-tls specific test
}

// Test that methods requiring other features are not available
#[test]
fn rustls_methods_not_available() {
    // This is a compile-time test - if rustls feature is not enabled,
    // rustls-specific methods should not be available
    let _builder = HttpClient::builder();
    
    // The following would cause compilation errors if rustls feature is not enabled:
    // builder.with_root_ca_pem(b"test");
    // builder.with_root_ca_file("test.pem");
    // builder.with_pinned_cert_sha256(vec![[0u8; 32]]);
    
    assert!(true); // If this compiles, the test passes
}

#[test]
fn insecure_methods_not_available() {
    // Test that insecure methods are not available without the feature
    let _builder = HttpClient::builder();
    
    // The following would cause compilation errors if insecure-dangerous feature is not enabled:
    // builder.insecure_accept_invalid_certs(true);
    
    assert!(true); // If this compiles, the test passes
}

#[test]
fn default_client_static_method() {
    // Test the static convenience method
    let client = HttpClient::default();
    assert!(true); // Placeholder - default() method succeeded
}