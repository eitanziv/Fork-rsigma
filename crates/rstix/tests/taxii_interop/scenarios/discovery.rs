//! §3.2–§3.3 Discovery and API Root (CSD01 Tables 6–8).

use rstix::taxii::{HttpsPolicy, TaxiiError};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer};

use crate::harness::support::{
    RstixUserAgent, api_root_body, discovery_body, interop_client, mount_discovery, taxii_error,
    taxii_json,
};

pub async fn get_discovery() {
    let server = MockServer::start().await;
    mount_discovery(&server, discovery_body(&server)).await;

    let client = interop_client(&server);
    let discovery = client.discover().await.expect("discover");
    assert!(!discovery.api_roots.is_empty());
    let base = url::Url::parse(&format!("{}/", server.uri().trim_end_matches('/'))).expect("url");
    let roots = discovery
        .resolved_api_roots(&base, HttpsPolicy::Allowed)
        .expect("resolve");
    assert!(roots.iter().any(|u| u.as_str().contains("/api1/")));
    assert!(roots.iter().any(|u| u.as_str().contains("/api2/")));
}

pub async fn get_api_root() {
    let server = MockServer::start().await;
    // Table 7 uses relative /api2/ after discovery.
    Mock::given(method("GET"))
        .and(path("/api2/"))
        .and(RstixUserAgent)
        .respond_with(taxii_json(200, api_root_body()))
        .mount(&server)
        .await;

    let client = interop_client(&server);
    let url = format!("{}/api2/", server.uri().trim_end_matches('/'));
    let root = client.api_root(&url).await.expect("api root");
    assert_eq!(root.title, "Sharing Group 2");
    assert_eq!(
        root.description.as_deref(),
        Some("This sharing group shares intelligence")
    );
    assert_eq!(root.max_content_length, 104857600);
    assert!(
        root.versions
            .iter()
            .any(|v| v.contains("taxii+json") && v.contains("2.1"))
    );
}

pub async fn incorrect_api_root() {
    let server = MockServer::start().await;
    // Table 8: GET /api3/ → 404 (not collections under api3).
    Mock::given(method("GET"))
        .and(path("/api3/"))
        .and(RstixUserAgent)
        .respond_with(taxii_error(404, "Not Found"))
        .mount(&server)
        .await;

    let client = interop_client(&server);
    let url = format!("{}/api3/", server.uri().trim_end_matches('/'));
    let err = client.api_root(&url).await.expect_err("must be 404");
    assert!(matches!(err, TaxiiError::NotFound { .. }));
}
