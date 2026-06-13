use std::net::SocketAddr;
use std::time::Duration;
use tuic_server::camouflage::{start_http_redirect, start_https_proxy};
use tuic_server::config::{CamouflageConfig, Config};
use tuic_server::AppContext;
use std::sync::Arc;
use axum::http::StatusCode;
use reqwest::Client;
use std::collections::HashMap;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn test_http_redirect_no_panic() -> eyre::Result<()> {
    let http_addr: SocketAddr = "127.0.0.1:0".parse()?;
    let https_addr: SocketAddr = "127.0.0.1:8443".parse()?;
    
    let listener = tokio::net::TcpListener::bind(http_addr).await?;
    let bound_addr = listener.local_addr()?;
    drop(listener); // We'll re-bind in start_http_redirect
    
    start_http_redirect(bound_addr, https_addr).await?;
    
    // Give it a moment to start
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
        
    // Test with absolute URI (some clients might send this)
    let res = client.get(format!("http://{}/test", bound_addr)).send().await?;
    assert_eq!(res.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(res.headers().get("location").unwrap(), "https://127.0.0.1:8443/test");

    // Test with relative URI (standard for curl)
    // We can simulate this by using a raw TCP stream or just rely on reqwest's behavior
    // reqwest always sends absolute URIs or Host header + path.
    
    Ok(())
}

#[tokio::test]
async fn test_https_camouflage_fallback() -> eyre::Result<()> {
    #[cfg(feature = "aws-lc-rs")]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    #[cfg(feature = "ring")]
    let _ = rustls::crypto::ring::default_provider().install_default();

    // This test ensures that the HTTPS proxy handles requests via fallback
    // We need a dummy backend
    let backend_app = axum::Router::new().route("/", axum::routing::get(|| async { "backend" }));
    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let backend_addr = backend_listener.local_addr()?;
    tokio::spawn(async move {
        axum::serve(backend_listener, backend_app).await.unwrap();
    });
    
    let mut cfg = Config::default();
    cfg.camouflage = Some(CamouflageConfig {
        enabled: true,
        reverse_proxy_url: format!("http://{}", backend_addr),
        ..Default::default()
    });
    
    let ctx = Arc::new(AppContext {
        cfg,
        online_counter: HashMap::new(),
        online_clients: moka::future::Cache::new(10),
        traffic_stats: HashMap::new(),
        cancel: CancellationToken::new(),
    });
    
    let https_addr: SocketAddr = "127.0.0.1:0".parse()?;
    let listener = tokio::net::TcpListener::bind(https_addr).await?;
    let bound_https_addr = listener.local_addr()?;
    drop(listener);

    // Self-signed cert for testing
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert);
    let priv_key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], priv_key)?;
    
    start_https_proxy(ctx, bound_https_addr, tls_config).await?;
    
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
        
    let res = client.get(format!("https://{}/some/random/path", bound_https_addr)).send().await?;
    // It should be forwarded to backend, but backend only has "/"
    // So backend returns 404, but it's returned BY THE BACKEND
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    
    let res = client.get(format!("https://{}/", bound_https_addr)).send().await?;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.text().await?, "backend");
    
    Ok(())
}

#[tokio::test]
async fn test_https_camouflage_header_preservation() -> eyre::Result<()> {
    #[cfg(feature = "aws-lc-rs")]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    #[cfg(feature = "ring")]
    let _ = rustls::crypto::ring::default_provider().install_default();

    let backend_app = axum::Router::new().route("/", axum::routing::get(|| async {
        (
            [
                (axum::http::header::CONTENT_TYPE, "application/octet-stream"),
                (axum::http::header::SERVER, "test-server"),
                (axum::http::header::HeaderName::from_static("x-custom-header"), "custom-value"),
            ],
            "backend content"
        )
    }));
    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let backend_addr = backend_listener.local_addr()?;
    tokio::spawn(async move {
        axum::serve(backend_listener, backend_app).await.unwrap();
    });
    
    let mut cfg = Config::default();
    cfg.camouflage = Some(CamouflageConfig {
        enabled: true,
        reverse_proxy_url: format!("http://{}", backend_addr),
        ..Default::default()
    });
    
    let ctx = Arc::new(AppContext {
        cfg,
        online_counter: HashMap::new(),
        online_clients: moka::future::Cache::new(10),
        traffic_stats: HashMap::new(),
        cancel: CancellationToken::new(),
    });
    
    let https_addr: SocketAddr = "127.0.0.1:0".parse()?;
    let listener = tokio::net::TcpListener::bind(https_addr).await?;
    let bound_https_addr = listener.local_addr()?;
    drop(listener);

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert);
    let priv_key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], priv_key)?;
    
    start_https_proxy(ctx, bound_https_addr, tls_config).await?;
    
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
        
    let res = client.get(format!("https://{}/", bound_https_addr)).send().await?;
    assert_eq!(res.status(), StatusCode::OK);
    
    assert_eq!(res.headers().get(axum::http::header::CONTENT_TYPE).unwrap(), "application/octet-stream");
    assert_eq!(res.headers().get(axum::http::header::SERVER).unwrap(), "test-server");
    assert_eq!(res.headers().get("x-custom-header").unwrap(), "custom-value");
    // Content-Length should be present now
    assert!(res.headers().get(axum::http::header::CONTENT_LENGTH).is_some());
    assert_eq!(res.headers().get(axum::http::header::CONTENT_LENGTH).unwrap(), "15"); // "backend content".len()

    Ok(())
}
