//! §3.13.1 TAXII standard filters (Mandatory Table 51 rows).

use rstix::core::{StixId, TaxiiTimestamp};
use rstix::taxii::{TaxiiError, TaxiiFilter, VersionFilter};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer};

use crate::harness::support::{
    API_ROOT, COL_READ_WRITE, INDICATOR_ID, RstixUserAgent, api_root_url, indicator_object,
    interop_client, mount_readable_collection, taxii_error, taxii_json,
};

async fn objects_with_filter(filter: TaxiiFilter, expected_query: &[(&str, &str)]) {
    let server = MockServer::start().await;
    mount_readable_collection(&server).await;

    let mut mock = Mock::given(method("GET"))
        .and(path(format!(
            "{API_ROOT}collections/{COL_READ_WRITE}/objects/"
        )))
        .and(RstixUserAgent);
    for (k, v) in expected_query {
        mock = mock.and(query_param(*k, *v));
    }
    mock.respond_with(taxii_json(
        200,
        serde_json::json!({
            "objects": [indicator_object()],
            "more": false
        }),
    ))
    .mount(&server)
    .await;

    let client = interop_client(&server);
    let page = client
        .objects(&api_root_url(&server), COL_READ_WRITE, filter)
        .await
        .expect("filtered objects");
    assert_eq!(page.value.objects.len(), 1);
}

pub async fn added_after() {
    let ts = TaxiiTimestamp::parse("2018-01-01T00:00:00.000000Z").expect("ts");
    objects_with_filter(
        TaxiiFilter::new().added_after(ts),
        &[("added_after", "2018-01-01T00:00:00.000000Z")],
    )
    .await;
}

pub async fn limit() {
    objects_with_filter(TaxiiFilter::new().limit(1), &[("limit", "1")]).await;
}

pub async fn match_id() {
    let id: StixId = INDICATOR_ID.parse().expect("id");
    objects_with_filter(
        TaxiiFilter::new().object_id(id),
        &[("match[id]", INDICATOR_ID)],
    )
    .await;
}

pub async fn match_type() {
    objects_with_filter(
        TaxiiFilter::new().object_type("indicator"),
        &[("match[type]", "indicator")],
    )
    .await;
}

pub async fn match_version() {
    let mut filter = TaxiiFilter::new();
    filter.version = VersionFilter::First;
    objects_with_filter(filter, &[("match[version]", "first")]).await;
}

pub async fn match_spec_version() {
    objects_with_filter(
        TaxiiFilter::new().spec_version("2.1"),
        &[("match[spec_version]", "2.1")],
    )
    .await;
}

pub async fn logical_or() {
    // Comma-separated values within one match field = OR (CSD01 §3.13.1.7).
    objects_with_filter(
        TaxiiFilter::new()
            .object_type("indicator")
            .object_type("malware"),
        &[("match[type]", "indicator,malware")],
    )
    .await;
}

pub async fn logical_and() {
    let id: StixId = INDICATOR_ID.parse().expect("id");
    objects_with_filter(
        TaxiiFilter::new()
            .object_type("indicator")
            .object_id(id),
        &[("match[type]", "indicator"), ("match[id]", INDICATOR_ID)],
    )
    .await;
}

pub async fn logical_or_and() {
    let id: StixId = INDICATOR_ID.parse().expect("id");
    objects_with_filter(
        TaxiiFilter::new()
            .object_type("indicator")
            .object_type("malware")
            .object_id(id),
        &[
            ("match[type]", "indicator,malware"),
            ("match[id]", INDICATOR_ID),
        ],
    )
    .await;
}

pub async fn duplicate_filter() {
    // CSD01 Table 42: duplicate `match[type]=…&match[type]=…` is a malformed request.
    // A compliant TXC encodes OR as a single comma-joined parameter (never duplicate keys).
    let filter = TaxiiFilter::new()
        .object_type("campaign")
        .object_type("malware");
    let pairs = filter.to_query_pairs().expect("encode");
    let type_keys: Vec<_> = pairs.iter().filter(|(k, _)| k == "match[type]").collect();
    assert_eq!(
        type_keys.len(),
        1,
        "TXC must not emit duplicate match[type] keys"
    );
    assert_eq!(type_keys[0].1, "campaign,malware");

    // TXC must still process a 400 Bad Request if the server rejects a filter request.
    let server = MockServer::start().await;
    mount_readable_collection(&server).await;
    Mock::given(method("GET"))
        .and(path(format!(
            "{API_ROOT}collections/{COL_READ_WRITE}/objects/"
        )))
        .and(RstixUserAgent)
        .and(query_param("match[type]", "campaign,malware"))
        .respond_with(taxii_error(400, "Bad Request"))
        .mount(&server)
        .await;

    let client = interop_client(&server);
    let err = client
        .objects(&api_root_url(&server), COL_READ_WRITE, filter)
        .await
        .expect_err("server may reject filter");
    assert!(matches!(err, TaxiiError::BadRequest { .. }));
}
