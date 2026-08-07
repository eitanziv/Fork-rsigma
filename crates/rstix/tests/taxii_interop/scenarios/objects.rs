//! §3.6–§3.10, §3.12 Objects / manifest / versions / add / delete.

use rstix::core::StixId;
use rstix::taxii::{TaxiiEnvelope, TaxiiError};
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer};

use crate::harness::support::{
    API_ROOT, COL_READ_WRITE, COL_WRITE_ONLY, INDICATOR_ID, RstixUserAgent, TAXII_MEDIA,
    api_root_url, indicator_object, indicator_stix_object, interop_client, mount_readable_collection,
    mount_write_collection, status_complete, taxii_error, taxii_json, taxii_json_with_date_headers,
};

pub async fn get_manifest() {
    let server = MockServer::start().await;
    mount_readable_collection(&server).await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{API_ROOT}collections/{COL_READ_WRITE}/manifest/"
        )))
        .and(RstixUserAgent)
        .respond_with(taxii_json_with_date_headers(
            200,
            serde_json::json!({
                "objects": [{
                    "id": INDICATOR_ID,
                    "date_added": "2018-01-18T11:11:13.000Z",
                    "version": "2018-01-18T11:11:13.000Z",
                    "media_type": "application/stix+json;version=2.1"
                }],
                "more": false
            }),
            "2018-01-18T11:11:13.000Z",
            "2018-01-18T11:11:13.000Z",
        ))
        .mount(&server)
        .await;

    let client = interop_client(&server);
    let page = client
        .manifest(
            &api_root_url(&server),
            COL_READ_WRITE,
            rstix::taxii::TaxiiFilter::new(),
        )
        .await
        .expect("manifest");
    assert_eq!(page.value.objects.len(), 1);
    assert_eq!(page.value.objects[0].id, INDICATOR_ID);
    assert!(page.headers.date_added_first.is_some());
    assert!(page.headers.date_added_last.is_some());
}

pub async fn get_objects() {
    let server = MockServer::start().await;
    mount_readable_collection(&server).await;
    let mut second = indicator_object();
    second["id"] = serde_json::json!("indicator--57ec1fb8-7a4d-52ef-a18a-4018996dfbba");
    second["name"] = serde_json::json!("Bad IP CIDR");

    Mock::given(method("GET"))
        .and(path(format!(
            "{API_ROOT}collections/{COL_READ_WRITE}/objects/"
        )))
        .and(RstixUserAgent)
        .respond_with(taxii_json_with_date_headers(
            200,
            serde_json::json!({
                "objects": [indicator_object(), second],
                "more": false
            }),
            "2018-01-17T11:11:13.000Z",
            "2018-01-18T11:11:13.000Z",
        ))
        .mount(&server)
        .await;

    let client = interop_client(&server);
    let page = client
        .objects(
            &api_root_url(&server),
            COL_READ_WRITE,
            rstix::taxii::TaxiiFilter::new(),
        )
        .await
        .expect("objects");
    assert_eq!(page.value.objects.len(), 2, "Table 20: access to all objects");
    assert!(page.headers.date_added_first.is_some());
    assert!(page.headers.date_added_last.is_some());
}

pub async fn no_objects() {
    let server = MockServer::start().await;
    mount_readable_collection(&server).await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{API_ROOT}collections/{COL_READ_WRITE}/objects/"
        )))
        .and(RstixUserAgent)
        .respond_with(taxii_json(200, serde_json::json!({ "more": false })))
        .mount(&server)
        .await;

    let client = interop_client(&server);
    let page = client
        .objects(
            &api_root_url(&server),
            COL_READ_WRITE,
            rstix::taxii::TaxiiFilter::new(),
        )
        .await
        .expect("objects");
    assert!(page.value.objects.is_empty());
}

pub async fn get_object() {
    let server = MockServer::start().await;
    mount_readable_collection(&server).await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{API_ROOT}collections/{COL_READ_WRITE}/objects/{INDICATOR_ID}/"
        )))
        .and(RstixUserAgent)
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "objects": [indicator_object()],
                "more": false
            }),
        ))
        .mount(&server)
        .await;

    let client = interop_client(&server);
    let id: StixId = INDICATOR_ID.parse().expect("id");
    let page = client
        .get_object(
            &api_root_url(&server),
            COL_READ_WRITE,
            &id,
            rstix::taxii::ObjectByIdFilter::default(),
        )
        .await
        .expect("object");
    assert_eq!(page.value.objects.len(), 1);
}

pub async fn object_not_found() {
    let server = MockServer::start().await;
    mount_readable_collection(&server).await;
    let missing = "indicator--00000000-0000-0000-0000-000000000099";
    Mock::given(method("GET"))
        .and(path(format!(
            "{API_ROOT}collections/{COL_READ_WRITE}/objects/{missing}/"
        )))
        .and(RstixUserAgent)
        .respond_with(taxii_error(404, "Not Found"))
        .mount(&server)
        .await;

    let client = interop_client(&server);
    let id: StixId = missing.parse().expect("id");
    let err = client
        .get_object(
            &api_root_url(&server),
            COL_READ_WRITE,
            &id,
            rstix::taxii::ObjectByIdFilter::default(),
        )
        .await
        .expect_err("must be 404");
    assert!(matches!(err, TaxiiError::NotFound { .. }));
}

pub async fn get_versions() {
    let server = MockServer::start().await;
    mount_readable_collection(&server).await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{API_ROOT}collections/{COL_READ_WRITE}/objects/{INDICATOR_ID}/versions/"
        )))
        .and(RstixUserAgent)
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "versions": ["2018-01-17T11:11:13.000Z"],
                "more": false
            }),
        ))
        .mount(&server)
        .await;

    let client = interop_client(&server);
    let id: StixId = INDICATOR_ID.parse().expect("id");
    let page = client
        .object_versions(
            &api_root_url(&server),
            COL_READ_WRITE,
            &id,
            rstix::taxii::VersionsQueryFilter::default(),
        )
        .await
        .expect("versions");
    assert_eq!(page.value.versions.len(), 1);
}

pub async fn add_objects() {
    let server = MockServer::start().await;
    mount_write_collection(&server).await;
    Mock::given(method("POST"))
        .and(path(format!(
            "{API_ROOT}collections/{COL_WRITE_ONLY}/objects/"
        )))
        .and(RstixUserAgent)
        .and(header("content-type", TAXII_MEDIA))
        .and(body_string_contains("\"objects\""))
        .and(body_string_contains(INDICATOR_ID))
        .respond_with(taxii_json(202, status_complete()))
        .mount(&server)
        .await;

    let client = interop_client(&server);
    let status = client
        .add_objects(
            &api_root_url(&server),
            COL_WRITE_ONLY,
            &TaxiiEnvelope::new(vec![indicator_stix_object()]),
        )
        .await
        .expect("add");
    // CSD01 §3.10.1: total_count == success_count; failure/pending zero.
    assert_eq!(status.total_count, status.success_count);
    assert_eq!(status.failure_count, 0);
    assert_eq!(status.pending_count, 0);
}

pub async fn delete_object() {
    let server = MockServer::start().await;
    mount_readable_collection(&server).await;
    Mock::given(method("DELETE"))
        .and(path(format!(
            "{API_ROOT}collections/{COL_READ_WRITE}/objects/{INDICATOR_ID}/"
        )))
        .and(RstixUserAgent)
        .respond_with(taxii_json(200, serde_json::json!({})))
        .mount(&server)
        .await;

    let client = interop_client(&server);
    let id: StixId = INDICATOR_ID.parse().expect("id");
    client
        .delete_object(
            &api_root_url(&server),
            COL_READ_WRITE,
            &id,
            rstix::taxii::DeleteObjectFilter::default(),
        )
        .await
        .expect("delete");
}
