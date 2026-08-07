//! §3.11 Status (CSD01 Tables 27–28).

use rstix::taxii::StatusState;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer};

use crate::harness::support::{
    API_ROOT, RstixUserAgent, STATUS_ID, api_root_url, interop_client, status_complete,
    status_full, taxii_json,
};

pub async fn get_status() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}status/{STATUS_ID}/")))
        .and(RstixUserAgent)
        .respond_with(taxii_json(200, status_complete()))
        .mount(&server)
        .await;

    let client = interop_client(&server);
    let status = client
        .get_status(&api_root_url(&server), STATUS_ID)
        .await
        .expect("status");
    assert_eq!(status.id, STATUS_ID);
    assert_eq!(status.status, StatusState::Complete);
    assert_eq!(status.total_count, 1);
    assert_eq!(status.success_count, 1);
}

pub async fn get_all_status_properties() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}status/{STATUS_ID}/")))
        .and(RstixUserAgent)
        .respond_with(taxii_json(200, status_full()))
        .mount(&server)
        .await;

    let client = interop_client(&server);
    let status = client
        .get_status(&api_root_url(&server), STATUS_ID)
        .await
        .expect("status");
    // Table 28: all status properties present.
    assert_eq!(status.status, StatusState::Pending);
    assert!(status.request_timestamp.is_some());
    assert_eq!(status.total_count, 3);
    assert_eq!(status.success_count, 1);
    assert_eq!(status.failure_count, 1);
    assert_eq!(status.pending_count, 1);
    assert_eq!(status.successes.len(), 1);
    assert_eq!(status.failures.len(), 1);
    assert_eq!(status.pendings.len(), 1);
    assert!(status.successes[0].message.is_some());
    assert!(status.failures[0].version.is_some());
}
