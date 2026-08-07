//! §3.14 Pagination — versions pagination via X-TAXII-Date-Added-Last (CSD01 Tables 48–49).

use futures::StreamExt;
use rstix::core::StixId;
use rstix::taxii::VersionsQueryFilter;
use wiremock::matchers::{method, path};
use wiremock::{Match, Mock, MockServer, Request};

use crate::harness::support::{
    API_ROOT, COL_READ_WRITE, INDICATOR_ID, RstixUserAgent, api_root_url, interop_client,
    taxii_json_with_date_headers,
};

#[derive(Debug)]
struct MissingQueryParam(&'static str);

impl Match for MissingQueryParam {
    fn matches(&self, request: &Request) -> bool {
        !request.url.query_pairs().any(|(k, _)| k == self.0)
    }
}

#[derive(Debug)]
struct ExactQueryParam(&'static str, &'static str);

impl Match for ExactQueryParam {
    fn matches(&self, request: &Request) -> bool {
        request
            .url
            .query_pairs()
            .any(|(k, v)| k == self.0 && v == self.1)
    }
}

pub async fn pagination() {
    let server = MockServer::start().await;
    let id: StixId = INDICATOR_ID.parse().expect("id");
    let versions_path =
        format!("{API_ROOT}collections/{COL_READ_WRITE}/objects/{INDICATOR_ID}/versions/");

    // Table 48: first versions page with more=true + X-TAXII-Date-Added-Last.
    Mock::given(method("GET"))
        .and(path(versions_path.as_str()))
        .and(RstixUserAgent)
        .and(MissingQueryParam("added_after"))
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
        .expect(1)
        .mount(&server)
        .await;

    // Table 49: subsequent request uses added_after from X-TAXII-Date-Added-Last.
    Mock::given(method("GET"))
        .and(path(versions_path.as_str()))
        .and(RstixUserAgent)
        .and(ExactQueryParam(
            "added_after",
            "2020-11-03T12:30:59.000000Z",
        ))
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
        .expect(1)
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
