//! §3.4–§3.5 Collections.

use rstix::taxii::{TaxiiEnvelope, TaxiiError};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer};

use crate::harness::support::{
    API_ROOT, COL_MISSING, COL_NO_RW, COL_READ_ONLY, COL_READ_WRITE, COL_WRITE_ONLY, RstixUserAgent,
    api_root_url, collection_body, collections_body, indicator_stix_object, interop_client,
    taxii_error, taxii_json,
};

pub async fn get_collections() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/")))
        .and(RstixUserAgent)
        .respond_with(taxii_json(200, collections_body()))
        .mount(&server)
        .await;

    let client = interop_client(&server);
    let collections = client
        .collections(&api_root_url(&server))
        .await
        .expect("collections");
    assert_eq!(collections.len(), 4);
    // TXS MUST sort by id ascending (§2.1.7); TXC must accept the ordered list.
    let ids: Vec<_> = collections.iter().map(|c| c.id.as_str()).collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted, "collections must be ordered by id");
    assert!(
        collections
            .iter()
            .any(|c| c.id == COL_WRITE_ONLY && !c.can_read && c.can_write)
    );
    assert!(
        collections
            .iter()
            .any(|c| c.id == COL_READ_WRITE && c.can_read && c.can_write)
    );
}

pub async fn write_only_collection() {
    get_collection(COL_WRITE_ONLY, "Collection 1", false, true).await;
}

pub async fn read_write_collection() {
    get_collection(COL_READ_WRITE, "Collection 3", true, true).await;
}

pub async fn read_only_collection() {
    get_collection(COL_READ_ONLY, "Collection 2", true, false).await;
}

pub async fn no_read_no_write_collection() {
    get_collection(COL_NO_RW, "Collection 4", false, false).await;
}

async fn get_collection(id: &str, title: &str, can_read: bool, can_write: bool) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/{id}/")))
        .and(RstixUserAgent)
        .respond_with(taxii_json(
            200,
            collection_body(id, title, can_read, can_write),
        ))
        .mount(&server)
        .await;

    let client = interop_client(&server);
    let col = client
        .collection(&api_root_url(&server), id)
        .await
        .expect("collection");
    assert_eq!(col.id, id);
    assert_eq!(col.title, title);
    assert_eq!(col.can_read, can_read);
    assert_eq!(col.can_write, can_write);
}

pub async fn read_write_only_forbidden() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/{COL_WRITE_ONLY}/")))
        .and(RstixUserAgent)
        .respond_with(taxii_json(
            200,
            collection_body(COL_WRITE_ONLY, "Collection 1", false, true),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{API_ROOT}collections/{COL_WRITE_ONLY}/objects/"
        )))
        .and(RstixUserAgent)
        .respond_with(taxii_error(403, "Forbidden"))
        .mount(&server)
        .await;

    let client = interop_client(&server);
    let err = client
        .objects(
            &api_root_url(&server),
            COL_WRITE_ONLY,
            rstix::taxii::TaxiiFilter::new(),
        )
        .await
        .expect_err("must be 403");
    assert!(matches!(err, TaxiiError::Forbidden { .. }));
}

pub async fn write_read_only_forbidden() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/{COL_READ_ONLY}/")))
        .and(RstixUserAgent)
        .respond_with(taxii_json(
            200,
            collection_body(COL_READ_ONLY, "Collection 2", true, false),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(API_ROOT))
        .and(RstixUserAgent)
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "title": "Api Root Under Test",
                "versions": ["application/taxii+json;version=2.1"],
                "max_content_length": 104857600
            }),
        ))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "{API_ROOT}collections/{COL_READ_ONLY}/objects/"
        )))
        .and(RstixUserAgent)
        .respond_with(taxii_error(403, "Forbidden"))
        .mount(&server)
        .await;

    let client = interop_client(&server);
    let err = client
        .add_objects(
            &api_root_url(&server),
            COL_READ_ONLY,
            &TaxiiEnvelope::new(vec![indicator_stix_object()]),
        )
        .await
        .expect_err("must be 403");
    assert!(matches!(err, TaxiiError::Forbidden { .. }));
}

pub async fn delete_forbidden() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/{COL_READ_ONLY}/")))
        .and(RstixUserAgent)
        .respond_with(taxii_json(
            200,
            collection_body(COL_READ_ONLY, "Collection 2", true, false),
        ))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(format!(
            "{API_ROOT}collections/{COL_READ_ONLY}/objects/indicator--deadbeef-0000-0000-0000-000000000001/"
        )))
        .and(RstixUserAgent)
        .respond_with(taxii_error(403, "Forbidden"))
        .mount(&server)
        .await;

    let client = interop_client(&server);
    let id: rstix::core::StixId = "indicator--deadbeef-0000-0000-0000-000000000001"
        .parse()
        .expect("id");
    let err = client
        .delete_object(
            &api_root_url(&server),
            COL_READ_ONLY,
            &id,
            rstix::taxii::DeleteObjectFilter::default(),
        )
        .await
        .expect_err("must be 403");
    assert!(matches!(err, TaxiiError::Forbidden { .. }));
}

pub async fn delete_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/{COL_NO_RW}/")))
        .and(RstixUserAgent)
        .respond_with(taxii_json(
            200,
            collection_body(COL_NO_RW, "Collection 4", false, false),
        ))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(format!(
            "{API_ROOT}collections/{COL_NO_RW}/objects/indicator--deadbeef-0000-0000-0000-000000000001/"
        )))
        .and(RstixUserAgent)
        .respond_with(taxii_error(404, "Not Found"))
        .mount(&server)
        .await;

    let client = interop_client(&server);
    let id: rstix::core::StixId = "indicator--deadbeef-0000-0000-0000-000000000001"
        .parse()
        .expect("id");
    let err = client
        .delete_object(
            &api_root_url(&server),
            COL_NO_RW,
            &id,
            rstix::taxii::DeleteObjectFilter::default(),
        )
        .await
        .expect_err("must be 404");
    assert!(matches!(err, TaxiiError::NotFound { .. }));
}

pub async fn incorrect_collection() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/{COL_MISSING}/")))
        .and(RstixUserAgent)
        .respond_with(taxii_error(404, "Not Found"))
        .mount(&server)
        .await;

    let client = interop_client(&server);
    let err = client
        .collection(&api_root_url(&server), COL_MISSING)
        .await
        .expect_err("must be 404");
    assert!(matches!(err, TaxiiError::NotFound { .. }));
}
