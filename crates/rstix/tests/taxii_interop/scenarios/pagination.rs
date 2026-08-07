//! §3.14 Pagination — versions pagination via X-TAXII-Date-Added-Last (CSD01 Tables 48–49).

use futures::StreamExt;
use rstix::core::StixId;
use rstix::taxii::VersionsQueryFilter;
use wiremock::matchers::{method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer};

use crate::harness::support::{
    API_ROOT, COL_READ_WRITE, INDICATOR_ID, RstixUserAgent, api_root_url, interop_client,
    mount_readable_collection, taxii_json_with_date_headers,
};

pub async fn pagination() {
    let server = MockServer::start().await;
    mount_readable_collection(&server).await;
    let id: StixId = INDICATOR_ID.parse().expect("id");

    // Table 48: first versions page with more=true + X-TAXII-Date-Added-Last.
    Mock::given(method("GET"))
        .and(path(format!(
            "{API_ROOT}collections/{COL_READ_WRITE}/objects/{INDICATOR_ID}/versions/"
        )))
        .and(RstixUserAgent)
        .and(query_param_is_missing("added_after"))
        .respond_with(taxii_json_with_date_headers(
            200,
            serde_json::json!({
                "more": true,
                "versions": [
                    "2020-04-03T12:30:59.000Z",
                    "2021-05-03T12:30:59.000Z",
                    "2022-06-03T12:30:59.000Z"
                ]
            }),
            "2020-11-03T12:30:59.000Z",
            "2020-11-03T12:30:59.000Z",
        ))
        .mount(&server)
        .await;

    // Table 49: subsequent request uses added_after from X-TAXII-Date-Added-Last.
    Mock::given(method("GET"))
        .and(path(format!(
            "{API_ROOT}collections/{COL_READ_WRITE}/objects/{INDICATOR_ID}/versions/"
        )))
        .and(RstixUserAgent)
        .and(query_param("added_after", "2020-11-03T12:30:59.000000Z"))
        .respond_with(taxii_json_with_date_headers(
            200,
            serde_json::json!({
                "more": false,
                "versions": [
                    "2022-11-04T12:30:59.000Z",
                    "2022-12-04T12:30:59.000Z"
                ]
            }),
            "2020-12-04T12:30:59.000Z",
            "2020-12-04T12:30:59.000Z",
        ))
        .mount(&server)
        .await;

    let client = interop_client(&server);
    let mut stream = client.object_versions_stream(
        api_root_url(&server),
        COL_READ_WRITE,
        id,
        VersionsQueryFilter::default(),
    );
    let mut versions = Vec::new();
    while let Some(item) = stream.next().await {
        versions.push(item.expect("version"));
    }
    assert_eq!(
        versions.len(),
        5,
        "Tables 48–49: five versions across two pages"
    );
}
