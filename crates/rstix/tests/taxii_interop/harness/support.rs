//! Shared wiremock TXS helpers for TXC interop scenarios.

use rstix::model::StixObject;
use rstix::taxii::{
    BasicAuth, CapabilityPolicy, PostSubmitPolicy, PreflightPolicy, TaxiiClient, TaxiiClientConfig,
};
use wiremock::matchers::{header, method, path};
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

pub const TAXII_MEDIA: &str = "application/taxii+json;version=2.1";
pub const API_ROOT: &str = "/api1/";

/// OASIS example collection IDs from CSD01 Tables 10–19.
pub const COL_WRITE_ONLY: &str = "1105e147-e4c1-4566-8fb1-1046d181fbf8";
pub const COL_READ_WRITE: &str = "378e5de7-84a4-45e4-8a34-c02a43d0b657";
pub const COL_READ_ONLY: &str = "253900d3-b9dd-46df-8184-469380fae6d2";
/// Distinct id for no-read/no-write so mock routes do not collide with Tables 12–13 reuse of
/// `253900d3-…` under different permissions.
pub const COL_NO_RW: &str = "91a7b528-80eb-42ed-a74d-c6fbd5a26116";
pub const COL_MISSING: &str = "d021ecc8-ab8e-41ab-815e-911c7e329f88";

pub const INDICATOR_ID: &str = "indicator--252c7c11-daf2-42bd-843b-be65edca9f61";
pub const STATUS_ID: &str = "2d086da7-4bdc-4f91-900e-d77486753710";

/// CSD01 §2.1.4 — TXC MUST send software name/version in User-Agent.
#[derive(Debug)]
pub struct RstixUserAgent;

impl Match for RstixUserAgent {
    fn matches(&self, request: &Request) -> bool {
        request
            .headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ua| ua.starts_with("rstix/"))
    }
}

pub fn taxii_json(status: u16, body: serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_raw(body.to_string(), TAXII_MEDIA)
}

pub fn taxii_json_with_date_headers(
    status: u16,
    body: serde_json::Value,
    first: &str,
    last: &str,
) -> ResponseTemplate {
    taxii_json(status, body)
        .insert_header("X-TAXII-Date-Added-First", first)
        .insert_header("X-TAXII-Date-Added-Last", last)
}

pub fn taxii_error(status: u16, title: &str) -> ResponseTemplate {
    taxii_json(
        status,
        serde_json::json!({
            "title": title,
            "http_status": status.to_string(),
        }),
    )
}

pub fn taxii_unauthorized() -> ResponseTemplate {
    taxii_error(401, "Unauthorized").insert_header(
        "WWW-Authenticate",
        r#"Basic realm="taxii", type=1, title="Login to \"apps\"", Basic realm="simple""#,
    )
}

pub fn api_root_url(server: &MockServer) -> String {
    format!("{}{}", server.uri().trim_end_matches('/'), API_ROOT)
}

/// Interop client: Basic auth, preflight off (server returns 403), capability off.
pub fn interop_client(server: &MockServer) -> TaxiiClient {
    TaxiiClient::new(interop_config(server)).expect("client")
}

pub fn interop_config(server: &MockServer) -> TaxiiClientConfig {
    TaxiiClientConfig::new(server.uri())
        .allow_insecure_http(true)
        .auth(BasicAuth::new("test", "Passw0rd!"))
        .preflight(PreflightPolicy::Disabled)
        .capability(CapabilityPolicy::Disabled)
        .post_submit(PostSubmitPolicy::ReturnInitial)
}

pub fn interop_client_no_auth(server: &MockServer) -> TaxiiClient {
    TaxiiClient::new(
        TaxiiClientConfig::new(server.uri())
            .allow_insecure_http(true)
            .preflight(PreflightPolicy::Disabled)
            .capability(CapabilityPolicy::Disabled)
            .post_submit(PostSubmitPolicy::ReturnInitial),
    )
    .expect("client")
}

pub fn interop_client_bad_auth(server: &MockServer) -> TaxiiClient {
    TaxiiClient::new(
        TaxiiClientConfig::new(server.uri())
            .allow_insecure_http(true)
            .auth(BasicAuth::new("test", "wrong-password"))
            .preflight(PreflightPolicy::Disabled)
            .capability(CapabilityPolicy::Disabled)
            .post_submit(PostSubmitPolicy::ReturnInitial),
    )
    .expect("client")
}

pub fn discovery_body(server: &MockServer) -> serde_json::Value {
    serde_json::json!({
        "title": "TAXII Server Under Test",
        "description": "This TAXII Server contains test data",
        "default": format!("{}{}", server.uri().trim_end_matches('/'), API_ROOT),
        "api_roots": [
            format!("{}{}", server.uri().trim_end_matches('/'), API_ROOT),
            "/api2/"
        ]
    })
}

pub fn api_root_body() -> serde_json::Value {
    serde_json::json!({
        "title": "Sharing Group 2",
        "description": "This sharing group shares intelligence",
        "versions": ["application/taxii+json;version=2.1"],
        "max_content_length": 104857600
    })
}

pub fn collection_body(id: &str, title: &str, can_read: bool, can_write: bool) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "title": title,
        "can_read": can_read,
        "can_write": can_write,
        "media_types": ["application/stix+json;version=2.1"]
    })
}

/// Collections already sorted by id ascending (TXS §2.1.7).
pub fn collections_body() -> serde_json::Value {
    let mut cols = vec![
        collection_body(COL_WRITE_ONLY, "Collection 1", false, true),
        collection_body(COL_NO_RW, "Collection 4", false, false),
        collection_body(COL_READ_ONLY, "Collection 2", true, false),
        collection_body(COL_READ_WRITE, "Collection 3", true, true),
    ];
    cols.sort_by(|a, b| a["id"].as_str().unwrap().cmp(b["id"].as_str().unwrap()));
    serde_json::json!({ "collections": cols })
}

pub async fn mount_readable_collection(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/{COL_READ_WRITE}/")))
        .and(RstixUserAgent)
        .respond_with(taxii_json(
            200,
            collection_body(COL_READ_WRITE, "Collection 3", true, true),
        ))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(API_ROOT))
        .and(RstixUserAgent)
        .respond_with(taxii_json(200, api_root_body()))
        .mount(server)
        .await;
}

pub async fn mount_write_collection(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/{COL_WRITE_ONLY}/")))
        .and(RstixUserAgent)
        .respond_with(taxii_json(
            200,
            collection_body(COL_WRITE_ONLY, "Collection 1", false, true),
        ))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(API_ROOT))
        .and(RstixUserAgent)
        .respond_with(taxii_json(200, api_root_body()))
        .mount(server)
        .await;
}

pub fn indicator_object() -> serde_json::Value {
    serde_json::json!({
        "type": "indicator",
        "spec_version": "2.1",
        "id": INDICATOR_ID,
        "created": "2018-01-17T11:11:13.000Z",
        "modified": "2018-01-17T11:11:13.000Z",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "indicator_types": ["malicious-activity"],
        "name": "Bad IP1",
        "pattern": "[ipv4-addr:value = '198.51.100.1']",
        "pattern_type": "stix",
        "valid_from": "2018-01-01T00:00:00.000Z"
    })
}

pub fn indicator_stix_object() -> StixObject {
    let bundle = serde_json::json!({
        "type": "bundle",
        "id": "bundle--00000000-0000-0000-0000-000000000001",
        "objects": [indicator_object()]
    });
    rstix::parse_bundle(&bundle.to_string())
        .expect("indicator")
        .objects()[0]
        .clone()
}

pub fn status_complete() -> serde_json::Value {
    serde_json::json!({
        "id": STATUS_ID,
        "status": "complete",
        "total_count": 1,
        "success_count": 1,
        "failure_count": 0,
        "pending_count": 0
    })
}

/// Table 28 — full status resource for §3.11.2.
pub fn status_full() -> serde_json::Value {
    serde_json::json!({
        "id": STATUS_ID,
        "status": "pending",
        "request_timestamp": "2016-11-02T12:34:34.123450Z",
        "total_count": 3,
        "success_count": 1,
        "successes": [{
            "id": "indicator--c410e480-e42b-47d1-9476-85307c12bcbf",
            "version": "2022-01-01T12:02:41.312Z",
            "message": "successfully processed!"
        }],
        "failure_count": 1,
        "failures": [{
            "id": "indicator--19ef5a33-ef0f-43e0-82e6-8fdb02fb1fb0",
            "version": "2022-01-02T12:02:41.312Z",
            "message": "this object failed STIX validation"
        }],
        "pending_count": 1,
        "pendings": [{
            "id": "indicator--b69a2dbd-6eeb-4a63-8796-80ce4bc2c704",
            "version": "2022-01-01T12:03:41.312Z",
            "message": "STIX validation in progress"
        }]
    })
}

/// Mount discovery with User-Agent gate (CSD01 §2.1.4).
pub async fn mount_discovery(server: &MockServer, body: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .and(RstixUserAgent)
        .and(header("accept", TAXII_MEDIA))
        .respond_with(taxii_json(200, body))
        .mount(server)
        .await;
}
