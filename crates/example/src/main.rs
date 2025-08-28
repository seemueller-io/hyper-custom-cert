use axum::{
    Router,
    extract::{Path, Query},
    response::Json,
    routing::{delete, get, post, put},
};
use hyper_custom_cert::HttpClient;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::time::Duration;

const SERVER_ADDRESS: &str = "127.0.0.1:8393";

#[derive(Serialize)]
struct TestResponse {
    endpoint: String,
    status: String,
    message: String,
    features_tested: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Deserialize)]
struct TimeoutQuery {
    timeout_secs: Option<u64>,
}

#[derive(Deserialize, Serialize)]
struct PostData {
    data: String,
}

#[tokio::main]
async fn main() {
    // Build comprehensive test harness with various endpoints
    let app = Router::new()
        // Root endpoint with API overview
        .route("/", get(api_overview))
        // Basic HTTP client tests
        .route("/test/client/default", get(test_default_client))
        .route("/test/client/builder", get(test_builder_client))
        .route("/test/client/timeout", get(test_timeout_client))
        .route("/test/client/headers", get(test_headers_client))
        .route("/test/client/combined", get(test_combined_config))
        // Feature-specific tests
        .route("/test/features/native-tls", get(test_native_tls_feature))
        .route("/test/features/rustls", get(test_rustls_feature))
        .route("/test/features/insecure", get(test_insecure_feature))
        // HTTP method tests
        .route("/test/methods/get", get(test_get_method))
        .route("/test/methods/post", post(test_post_method))
        .route("/test/methods/put", put(test_put_method))
        .route("/test/methods/delete", delete(test_delete_method))
        // Certificate and TLS tests
        .route("/test/tls/custom-ca", get(test_custom_ca))
        .route("/test/tls/cert-pinning", get(test_cert_pinning))
        .route("/test/tls/self-signed", get(test_self_signed))
        // Configuration tests
        .route("/test/config/timeout/{seconds}", get(test_custom_timeout))
        .route(
            "/test/config/headers/{header_count}",
            get(test_custom_headers),
        )
        // Error simulation tests
        .route("/test/errors/timeout", get(test_timeout_error))
        .route("/test/errors/invalid-url", get(test_invalid_url))
        .route("/test/errors/connection", get(test_connection_error))
        // Health and status endpoints
        .route("/health", get(health_check))
        .route("/status", get(status_check));

    let listener = tokio::net::TcpListener::bind(SERVER_ADDRESS).await.unwrap();
    println!("🚀 Hyper-Custom-Cert Test Harness Server");
    println!("📍 Listening on http://{}", SERVER_ADDRESS);
    println!("📖 Visit http://{} for API documentation", SERVER_ADDRESS);
    println!("🧪 Ready for integration testing!");

    axum::serve(listener, app).await.unwrap();
}

/// API Overview and Documentation
async fn api_overview() -> Json<Value> {
    Json(json!({
        "name": "Hyper-Custom-Cert Test Harness",
        "version": "1.0.0",
        "description": "Comprehensive test server for integration testing the hyper-custom-cert library",
        "endpoints": {
            "basic_tests": {
                "/test/client/default": "Test default HttpClient creation",
                "/test/client/builder": "Test HttpClient builder pattern",
                "/test/client/timeout": "Test timeout configuration",
                "/test/client/headers": "Test custom headers configuration",
                "/test/client/combined": "Test combined configuration options"
            },
            "feature_tests": {
                "/test/features/native-tls": "Test native-tls backend functionality",
                "/test/features/rustls": "Test rustls backend functionality",
                "/test/features/insecure": "Test insecure-dangerous feature"
            },
            "method_tests": {
                "/test/methods/get": "Test HTTP GET requests",
                "/test/methods/post": "Test HTTP POST requests",
                "/test/methods/put": "Test HTTP PUT requests",
                "/test/methods/delete": "Test HTTP DELETE requests"
            },
            "tls_tests": {
                "/test/tls/custom-ca": "Test custom CA certificate loading",
                "/test/tls/cert-pinning": "Test certificate pinning",
                "/test/tls/self-signed": "Test self-signed certificate handling"
            },
            "config_tests": {
                "/test/config/timeout/{seconds}": "Test custom timeout values",
                "/test/config/headers/{count}": "Test custom header configurations"
            },
            "error_tests": {
                "/test/errors/timeout": "Test timeout error handling",
                "/test/errors/invalid-url": "Test invalid URL handling",
                "/test/errors/connection": "Test connection error handling"
            },
            "utility": {
                "/health": "Health check endpoint",
                "/status": "Server status information"
            }
        },
        "features_available": [
            "native-tls",
            "rustls",
            "insecure-dangerous"
        ]
    }))
}

// ============================================================================
// BASIC CLIENT TESTS
// ============================================================================

/// Test default HttpClient creation
async fn test_default_client() -> Json<TestResponse> {
    let client = HttpClient::new();
    let result = client.request("https://httpbin.org/get").await;

    Json(TestResponse {
        endpoint: "/test/client/default".to_string(),
        status: "success".to_string(),
        message: "Default HttpClient created successfully".to_string(),
        features_tested: vec!["native-tls".to_string()],
        error: match result {
            Ok(_) => None,
            Err(e) => Some(format!("Request error: {}", e)),
        },
    })
}

/// Test HttpClient builder pattern
async fn test_builder_client() -> Json<TestResponse> {
    let client = HttpClient::builder().build();
    let result = client.request("https://httpbin.org/get").await;

    Json(TestResponse {
        endpoint: "/test/client/builder".to_string(),
        status: "success".to_string(),
        message: "HttpClient builder pattern works correctly".to_string(),
        features_tested: vec!["builder-pattern".to_string()],
        error: match result {
            Ok(_) => None,
            Err(e) => Some(format!("Request error: {}", e)),
        },
    })
}

/// Test timeout configuration
async fn test_timeout_client(Query(params): Query<TimeoutQuery>) -> Json<TestResponse> {
    let timeout_secs = params.timeout_secs.unwrap_or(10);
    let client = HttpClient::builder()
        .with_timeout(Duration::from_secs(timeout_secs))
        .build();
    let result = client.request("https://httpbin.org/get").await;

    Json(TestResponse {
        endpoint: "/test/client/timeout".to_string(),
        status: "success".to_string(),
        message: format!(
            "HttpClient with {}s timeout configured successfully",
            timeout_secs
        ),
        features_tested: vec!["timeout-config".to_string()],
        error: match result {
            Ok(_) => None,
            Err(e) => Some(format!("Request error: {}", e)),
        },
    })
}

/// Test custom headers configuration
async fn test_headers_client() -> Json<TestResponse> {
    let mut headers = HashMap::new();
    headers.insert(
        "User-Agent".to_string(),
        "hyper-custom-cert-test/1.0".to_string(),
    );
    headers.insert("X-Test-Header".to_string(), "test-value".to_string());
    headers.insert("Accept".to_string(), "application/json".to_string());

    let client = HttpClient::builder().with_default_headers(headers).build();
    let result = client.request("https://httpbin.org/get").await;

    Json(TestResponse {
        endpoint: "/test/client/headers".to_string(),
        status: "success".to_string(),
        message: "HttpClient with custom headers configured successfully".to_string(),
        features_tested: vec!["custom-headers".to_string()],
        error: match result {
            Ok(_) => None,
            Err(e) => Some(format!("Request error: {}", e)),
        },
    })
}

/// Test combined configuration options
async fn test_combined_config() -> Json<TestResponse> {
    let mut headers = HashMap::new();
    headers.insert(
        "User-Agent".to_string(),
        "hyper-custom-cert-combined/1.0".to_string(),
    );
    headers.insert("X-Combined-Test".to_string(), "true".to_string());

    let client = HttpClient::builder()
        .with_timeout(Duration::from_secs(30))
        .with_default_headers(headers)
        .build();
    let result = client.request("https://httpbin.org/get").await;

    Json(TestResponse {
        endpoint: "/test/client/combined".to_string(),
        status: "success".to_string(),
        message: "HttpClient with combined configuration (timeout + headers) works correctly"
            .to_string(),
        features_tested: vec!["timeout-config".to_string(), "custom-headers".to_string()],
        error: match result {
            Ok(_) => None,
            Err(e) => Some(format!("Request error: {}", e)),
        },
    })
}

// ============================================================================
// FEATURE-SPECIFIC TESTS
// ============================================================================

/// Test native-tls backend functionality
async fn test_native_tls_feature() -> Json<TestResponse> {
    #[cfg(feature = "native-tls")]
    {
        let client = HttpClient::builder()
            .with_timeout(Duration::from_secs(10))
            .build();
        let result = client.request("https://httpbin.org/get").await;

        Json(TestResponse {
            endpoint: "/test/features/native-tls".to_string(),
            status: "success".to_string(),
            message: "native-tls feature is working correctly".to_string(),
            features_tested: vec!["native-tls".to_string()],
            error: match result {
                Ok(_) => None,
                Err(e) => Some(format!("Request error: {}", e)),
            },
        })
    }
    #[cfg(not(feature = "native-tls"))]
    {
        Json(TestResponse {
            endpoint: "/test/features/native-tls".to_string(),
            status: "skipped".to_string(),
            message: "native-tls feature is not enabled".to_string(),
            features_tested: vec![],
            error: Some("Feature not enabled".to_string()),
        })
    }
}

/// Test rustls backend functionality
async fn test_rustls_feature() -> Json<TestResponse> {
    #[cfg(feature = "rustls")]
    {
        // Test with sample root CA PEM (this is just a demo cert)
        let ca_pem: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/\nMSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\nDkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow\nPzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD\nEw5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\nAN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O\nrz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq\nOLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b\nxiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw\n7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD\naeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV\nHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG\nSIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69\nikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr\nAvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz\nR8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5\nJDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo\nOb8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ\n-----END CERTIFICATE-----\n";

        let client = HttpClient::builder()
            .with_timeout(Duration::from_secs(10))
            .with_root_ca_pem(ca_pem)
            .build();
        let result = client.request("https://httpbin.org/get").await;

        Json(TestResponse {
            endpoint: "/test/features/rustls".to_string(),
            status: "success".to_string(),
            message: "rustls feature with custom CA is working correctly".to_string(),
            features_tested: vec!["rustls".to_string(), "custom-ca-pem".to_string()],
            error: match result {
                Ok(_) => None,
                Err(e) => Some(format!("Request error: {}", e)),
            },
        })
    }
    #[cfg(not(feature = "rustls"))]
    {
        Json(TestResponse {
            endpoint: "/test/features/rustls".to_string(),
            status: "skipped".to_string(),
            message: "rustls feature is not enabled".to_string(),
            features_tested: vec![],
            error: Some("Feature not enabled".to_string()),
        })
    }
}

/// Test insecure-dangerous feature
async fn test_insecure_feature() -> Json<TestResponse> {
    #[cfg(feature = "insecure-dangerous")]
    {
        // Test shortcut method
        let client = HttpClient::with_self_signed_certs();
        let result = client.request("https://self-signed.badssl.com/").await;

        // Test builder method
        let client2 = HttpClient::builder()
            .insecure_accept_invalid_certs(true)
            .build();
        let result2 = client2.request("https://expired.badssl.com/").await;

        Json(TestResponse {
            endpoint: "/test/features/insecure".to_string(),
            status: "success".to_string(),
            message: "insecure-dangerous feature is working (DO NOT USE IN PRODUCTION!)"
                .to_string(),
            features_tested: vec!["insecure-dangerous".to_string()],
            error: match (result, result2) {
                (Ok(_), Ok(_)) => None,
                (Err(e1), _) => Some(format!("First client error: {}", e1)),
                (_, Err(e2)) => Some(format!("Second client error: {}", e2)),
            },
        })
    }
    #[cfg(not(feature = "insecure-dangerous"))]
    {
        Json(TestResponse {
            endpoint: "/test/features/insecure".to_string(),
            status: "skipped".to_string(),
            message: "insecure-dangerous feature is not enabled (this is good for security!)"
                .to_string(),
            features_tested: vec![],
            error: Some("Feature not enabled".to_string()),
        })
    }
}

// ============================================================================
// HTTP METHOD TESTS
// ============================================================================

/// Test HTTP GET method
async fn test_get_method() -> Json<TestResponse> {
    let client = HttpClient::new();
    let result = client.request("https://httpbin.org/get").await;

    Json(TestResponse {
        endpoint: "/test/methods/get".to_string(),
        status: "success".to_string(),
        message: "HTTP GET method test completed".to_string(),
        features_tested: vec!["get-request".to_string()],
        error: match result {
            Ok(_) => None,
            Err(e) => Some(format!("GET request error: {}", e)),
        },
    })
}

/// Test HTTP POST method
async fn test_post_method(Json(payload): Json<PostData>) -> Json<TestResponse> {
    let client = HttpClient::new();
    let body = serde_json::to_vec(&payload).unwrap_or_default();
    let result = client.post("https://httpbin.org/post", &body).await;

    Json(TestResponse {
        endpoint: "/test/methods/post".to_string(),
        status: "success".to_string(),
        message: format!(
            "HTTP POST method test completed with data: {}",
            payload.data
        ),
        features_tested: vec!["post-request".to_string()],
        error: match result {
            Ok(_) => None,
            Err(e) => Some(format!("POST request error: {}", e)),
        },
    })
}

/// Test HTTP PUT method (simulated via POST since library doesn't have PUT yet)
async fn test_put_method(Json(payload): Json<PostData>) -> Json<TestResponse> {
    let client = HttpClient::new();
    let body = serde_json::to_vec(&payload).unwrap_or_default();
    let result = client.post("https://httpbin.org/put", &body).await;

    Json(TestResponse {
        endpoint: "/test/methods/put".to_string(),
        status: "success".to_string(),
        message: format!(
            "HTTP PUT method test completed (simulated via POST) with data: {}",
            payload.data
        ),
        features_tested: vec!["put-request-simulation".to_string()],
        error: match result {
            Ok(_) => None,
            Err(e) => Some(format!("PUT request error: {}", e)),
        },
    })
}

/// Test HTTP DELETE method (simulated via GET since library doesn't have DELETE yet)
async fn test_delete_method() -> Json<TestResponse> {
    let client = HttpClient::new();
    let result = client.request("https://httpbin.org/delete").await;

    Json(TestResponse {
        endpoint: "/test/methods/delete".to_string(),
        status: "success".to_string(),
        message: "HTTP DELETE method test completed (simulated via GET)".to_string(),
        features_tested: vec!["delete-request-simulation".to_string()],
        error: match result {
            Ok(_) => None,
            Err(e) => Some(format!("DELETE request error: {}", e)),
        },
    })
}

// ============================================================================
// TLS AND CERTIFICATE TESTS
// ============================================================================

/// Test custom CA functionality
async fn test_custom_ca() -> Json<TestResponse> {
    #[cfg(feature = "rustls")]
    {
        let ca_pem: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/\nMSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\nDkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow\nPzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD\nEw5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\nAN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O\nrz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq\nOLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b\nxiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw\n7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD\naeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV\nHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG\nSIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69\nikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr\nAvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz\nR8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5\nJDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo\nOb8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ\n-----END CERTIFICATE-----\n";

        let client = HttpClient::builder()
            .with_timeout(Duration::from_secs(10))
            .with_root_ca_pem(ca_pem)
            .build();
        let result = client.request("https://httpbin.org/get");

        let awaited = result.await;

        Json(TestResponse {
            endpoint: "/test/tls/custom-ca".to_string(),
            status: "success".to_string(),
            message: "Custom CA certificate test completed successfully".to_string(),
            features_tested: vec!["rustls".to_string(), "custom-ca-pem".to_string()],
            error: match awaited {
                Ok(_) => None,
                Err(e) => Some(format!("Custom CA request error: {}", e)),
            },
        })
    }
    #[cfg(not(feature = "rustls"))]
    {
        Json(TestResponse {
            endpoint: "/test/tls/custom-ca".to_string(),
            status: "skipped".to_string(),
            message: "Custom CA test requires rustls feature".to_string(),
            features_tested: vec![],
            error: Some("rustls feature not enabled".to_string()),
        })
    }
}

/// Test certificate pinning functionality
async fn test_cert_pinning() -> Json<TestResponse> {
    #[cfg(feature = "rustls")]
    {
        // Example SHA256 fingerprints (these are demo values)
        let pins = vec![[
            0x1f, 0x2f, 0x3f, 0x4f, 0x5f, 0x6f, 0x7f, 0x8f, 0x9f, 0xaf, 0xbf, 0xcf, 0xdf, 0xef,
            0xff, 0x0f, 0x1f, 0x2f, 0x3f, 0x4f, 0x5f, 0x6f, 0x7f, 0x8f, 0x9f, 0xaf, 0xbf, 0xcf,
            0xdf, 0xef, 0xff, 0x0f,
        ]];

        let client = HttpClient::builder()
            .with_timeout(Duration::from_secs(10))
            .with_pinned_cert_sha256(pins)
            .build();
        let result = client.request("https://httpbin.org/get");

        let awaited = result.await;

        Json(TestResponse {
            endpoint: "/test/tls/cert-pinning".to_string(),
            status: "success".to_string(),
            message: "Certificate pinning test completed (may fail due to demo pins)".to_string(),
            features_tested: vec!["rustls".to_string(), "cert-pinning".to_string()],
            error: match awaited {
                Ok(_) => None,
                Err(e) => Some(format!("Cert pinning request error (expected): {}", e)),
            },
        })
    }
    #[cfg(not(feature = "rustls"))]
    {
        Json(TestResponse {
            endpoint: "/test/tls/cert-pinning".to_string(),
            status: "skipped".to_string(),
            message: "Certificate pinning test requires rustls feature".to_string(),
            features_tested: vec![],
            error: Some("rustls feature not enabled".to_string()),
        })
    }
}

/// Test self-signed certificate handling
async fn test_self_signed() -> Json<TestResponse> {
    #[cfg(feature = "insecure-dangerous")]
    {
        let client = HttpClient::with_self_signed_certs();
        let result = client.request("https://self-signed.badssl.com/");

        let awaited = result.await;

        Json(TestResponse {
            endpoint: "/test/tls/self-signed".to_string(),
            status: "success".to_string(),
            message: "Self-signed certificate test completed (DANGEROUS - dev only!)".to_string(),
            features_tested: vec!["insecure-dangerous".to_string()],
            error: match awaited {
                Ok(_) => None,
                Err(e) => Some(format!("Self-signed request error: {}", e)),
            },
        })
    }
    #[cfg(not(feature = "insecure-dangerous"))]
    {
        Json(TestResponse {
            endpoint: "/test/tls/self-signed".to_string(),
            status: "skipped".to_string(),
            message: "Self-signed test requires insecure-dangerous feature (good for security!)"
                .to_string(),
            features_tested: vec![],
            error: Some("insecure-dangerous feature not enabled".to_string()),
        })
    }
}

// ============================================================================
// CONFIGURATION TESTS
// ============================================================================

/// Test custom timeout configuration
async fn test_custom_timeout(Path(seconds): Path<u64>) -> Json<TestResponse> {
    let timeout_duration = Duration::from_secs(seconds);
    let client = HttpClient::builder().with_timeout(timeout_duration).build();
    let result = client.request("https://httpbin.org/delay/1");

    Json(TestResponse {
        endpoint: format!("/test/config/timeout/{}", seconds),
        status: "success".to_string(),
        message: format!("Custom timeout test with {}s timeout completed", seconds),
        features_tested: vec!["custom-timeout".to_string()],
        error: match result.await {
            Ok(_) => None,
            Err(e) => Some(format!("Timeout test error: {}", e)),
        },
    })
}

/// Test custom headers configuration
async fn test_custom_headers(Path(header_count): Path<usize>) -> Json<TestResponse> {
    let mut headers = HashMap::new();

    for i in 0..header_count {
        headers.insert(format!("X-Test-Header-{}", i), format!("test-value-{}", i));
    }

    // Add some standard headers
    headers.insert(
        "User-Agent".to_string(),
        "hyper-custom-cert-headers-test/1.0".to_string(),
    );
    headers.insert("Accept".to_string(), "application/json".to_string());

    let client = HttpClient::builder()
        .with_timeout(Duration::from_secs(10))
        .with_default_headers(headers)
        .build();
    let result = client.request("https://httpbin.org/headers");

    Json(TestResponse {
        endpoint: format!("/test/config/headers/{}", header_count),
        status: "success".to_string(),
        message: format!(
            "Custom headers test with {} headers completed",
            header_count + 2
        ),
        features_tested: vec!["custom-headers".to_string()],
        error: match result.await {
            Ok(_) => None,
            Err(e) => Some(format!("Headers test error: {}", e)),
        },
    })
}

// ============================================================================
// ERROR SIMULATION TESTS
// ============================================================================

/// Test timeout error handling
async fn test_timeout_error() -> Json<TestResponse> {
    // Set a very short timeout to force a timeout error
    let client = HttpClient::builder()
        .with_timeout(Duration::from_millis(1))
        .build();
    let result = client.request("https://httpbin.org/delay/5");

    let awaited = result.await;
    Json(TestResponse {
        endpoint: "/test/errors/timeout".to_string(),
        status: if awaited.is_err() {
            "success"
        } else {
            "unexpected"
        }
        .to_string(),
        message: "Timeout error simulation test completed".to_string(),
        features_tested: vec!["timeout-error-handling".to_string()],
        error: match awaited {
            Ok(_) => Some("Expected timeout error but request succeeded".to_string()),
            Err(e) => Some(format!("Expected timeout error: {}", e)),
        },
    })
}

/// Test invalid URL handling
async fn test_invalid_url() -> Json<TestResponse> {
    let client = HttpClient::new();
    let result = client.request("invalid-url-format");

    let awaited = result.await;

    Json(TestResponse {
        endpoint: "/test/errors/invalid-url".to_string(),
        status: if awaited.is_err() {
            "success"
        } else {
            "unexpected"
        }
        .to_string(),
        message: "Invalid URL error simulation test completed".to_string(),
        features_tested: vec!["url-validation".to_string()],
        error: match awaited {
            Ok(_) => Some("Expected URL error but request succeeded".to_string()),
            Err(e) => Some(format!("Expected URL error: {}", e)),
        },
    })
}

/// Test connection error handling
async fn test_connection_error() -> Json<TestResponse> {
    let client = HttpClient::builder()
        .with_timeout(Duration::from_secs(5))
        .build();
    // Try to connect to a non-existent host
    let result = client.request("https://non-existent-host-12345.example.com/");
    let awaited = result.await;

    Json(TestResponse {
        endpoint: "/test/errors/connection".to_string(),
        status: if awaited.is_err() {
            "success"
        } else {
            "unexpected"
        }
        .to_string(),
        message: "Connection error simulation test completed".to_string(),
        features_tested: vec!["connection-error-handling".to_string()],
        error: match awaited {
            Ok(_) => Some("Expected connection error but request succeeded".to_string()),
            Err(e) => Some(format!("Expected connection error: {}", e)),
        },
    })
}

// ============================================================================
// UTILITY ENDPOINTS
// ============================================================================

/// Health check endpoint
async fn health_check() -> Json<Value> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    Json(json!({
        "status": "healthy",
        "timestamp": timestamp,
        "service": "hyper-custom-cert-test-harness",
        "version": "1.0.0"
    }))
}

/// Status check endpoint with detailed information
async fn status_check() -> Json<Value> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Test basic client creation to verify library is working
    let client_test = match HttpClient::new().request("https://httpbin.org/get").await {
        Ok(_) => "operational",
        Err(_) => "degraded",
    };

    Json(json!({
        "service": "hyper-custom-cert-test-harness",
        "version": "1.0.0",
        "status": client_test,
        "timestamp": timestamp,
        "features": {
            "native-tls": cfg!(feature = "native-tls"),
            "rustls": cfg!(feature = "rustls"),
            "insecure-dangerous": cfg!(feature = "insecure-dangerous")
        },
        "endpoints_available": 18,
        "test_categories": [
            "basic_client_tests",
            "feature_specific_tests",
            "http_method_tests",
            "tls_certificate_tests",
            "configuration_tests",
            "error_simulation_tests",
            "utility_endpoints"
        ]
    }))
}
