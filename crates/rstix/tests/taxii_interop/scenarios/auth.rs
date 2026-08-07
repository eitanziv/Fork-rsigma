//! §3.1 Authentication & Authorization (CSD01 Tables 2–5).

use rstix::taxii::{HttpsPolicy, TaxiiError};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer};

use crate::harness::support::{
    RstixUserAgent, discovery_body, interop_client, interop_client_bad_auth,
    interop_client_no_auth, taxii_unauthorized,
};

pub async fn missing_authorization() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .and(RstixUserAgent)
        .respond_with(taxii_unauthorized())
        .mount(&server)
        .await;

    let client = interop_client_no_auth(&server);
    let err = client.discover().await.expect_err("must be 401");
    match err {
        TaxiiError::Unauthorized { challenges, body } => {
            // CSD01 Table 2: two Basic challenges (auth-params must not become fake schemes).
            assert_eq!(challenges.len(), 2, "Table 2 WWW-Authenticate challenges");
            assert!(
                challenges
                    .iter()
                    .all(|c| c.scheme.eq_ignore_ascii_case("Basic"))
            );
            assert_eq!(
                body.as_ref().map(|b| b.title.as_str()),
                Some("Unauthorized")
            );
        }
        other => panic!("expected Unauthorized, got {other:?}"),
    }
}

pub async fn authorization_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .and(RstixUserAgent)
        .respond_with(taxii_unauthorized())
        .mount(&server)
        .await;

    let client = interop_client_bad_auth(&server);
    let err = client.discover().await.expect_err("must be 401");
    match err {
        TaxiiError::Unauthorized { challenges, .. } => {
            assert!(!challenges.is_empty());
        }
        other => panic!("expected Unauthorized, got {other:?}"),
    }
}

pub async fn certificate_auth() {
    crate::harness::mtls::certificate_auth().await;
}

pub async fn http_basic() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .and(RstixUserAgent)
        .and(header(
            "authorization",
            "Basic dGVzdDpQYXNzdzByZCE=", // test:Passw0rd!
        ))
        .respond_with(crate::harness::support::taxii_json(
            200,
            discovery_body(&server),
        ))
        .mount(&server)
        .await;

    let client = interop_client(&server);
    let discovery = client.discover().await.expect("discover");
    assert_eq!(discovery.title, "TAXII Server Under Test");
    // Absolute + relative api_roots (Table 5).
    let base = url::Url::parse(&format!("{}/", server.uri().trim_end_matches('/'))).expect("url");
    let roots = discovery
        .resolved_api_roots(&base, HttpsPolicy::Allowed)
        .expect("resolve");
    assert!(roots.len() >= 2);
    assert!(roots.iter().any(|u| u.as_str().contains("/api1/")));
    assert!(roots.iter().any(|u| u.as_str().contains("/api2/")));
}
