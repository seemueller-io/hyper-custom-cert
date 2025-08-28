use hyper_custom_cert::HttpClient;
use std::collections::HashMap;
use std::time::Duration;

#[tokio::main]
async fn main() {
    // Default secure client (uses OS trust store when built with default features)
    let mut headers = HashMap::new();
    headers.insert("x-app".into(), "example".into());

    let client = HttpClient::builder()
        .with_timeout(Duration::from_secs(10))
        .with_default_headers(headers)
        .build();

    // Demonstrate a request (now returns HttpResponse with raw body data)
    let _response = client
        .request("https://example.com")
        .await
        .expect("request should succeed on native targets");

    // Production with rustls + custom Root CA (e.g., self-signed for your private service)
    // Note: Requires building with: --no-default-features --features rustls
    #[cfg(feature = "rustls")]
    {
        // Option 1: Load CA certificate from raw PEM bytes
        let ca_pem: &[u8] =
            b"-----BEGIN CERTIFICATE-----\n...your root ca...\n-----END CERTIFICATE-----\n";
        let _rustls_client = HttpClient::builder()
            .with_timeout(Duration::from_secs(10))
            .with_root_ca_pem(ca_pem)
            .build();
        let _ = _rustls_client.request("https://private.local").await;

        // Option 2: Load CA certificate from a file path
        // Note: This will panic if the file doesn't exist - ensure your cert file is available
        // let _rustls_client_from_file = HttpClient::builder()
        //     .with_timeout(Duration::from_secs(10))
        //     .with_root_ca_file("path/to/your/root-ca.pem")
        //     .build();
        // let _ = _rustls_client_from_file.request("https://private.local");
    }

    // Local development only: accept invalid/self-signed certs (dangerous)
    // Build with: --features insecure-dangerous (or with rustls,insecure-dangerous)
    #[cfg(feature = "insecure-dangerous")]
    {
        // Shortcut:
        let _dev_client = HttpClient::with_self_signed_certs();
        let _ = _dev_client.request("https://localhost:8443").await;

        // Or explicit builder method:
        let _dev_client2 = HttpClient::builder()
            .insecure_accept_invalid_certs(true)
            .build();
        let _ = _dev_client2.request("https://localhost:8443").await;
    }

    println!("Example finished. See README for feature flags and commands.");
}
