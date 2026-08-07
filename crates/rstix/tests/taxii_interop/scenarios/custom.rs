//! §3.15 Custom Properties (CSD01 Table 50).

use rstix::taxii::TaxiiEnvelope;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer};

use crate::harness::support::{
    API_ROOT, COL_WRITE_ONLY, INDICATOR_ID, RstixUserAgent, STATUS_ID, TAXII_MEDIA, api_root_url,
    indicator_stix_object, interop_client, mount_write_collection, taxii_json,
};

const CLIENT_CUSTOM: &str = "x_18467e42_04f4_4505_93c8_9f1cf29e1045_test_client";
const SERVER_CUSTOM: &str = "x_f18dd923_7fdd_4c5c_94f3_807f556bce6b_test_server";

pub async fn custom_properties() {
    let server = MockServer::start().await;
    mount_write_collection(&server).await;

    Mock::given(method("POST"))
        .and(path(format!(
            "{API_ROOT}collections/{COL_WRITE_ONLY}/objects/"
        )))
        .and(RstixUserAgent)
        .and(header("content-type", TAXII_MEDIA))
        .and(body_string_contains(CLIENT_CUSTOM))
        .and(body_string_contains(INDICATOR_ID))
        .respond_with(taxii_json(
            202,
            serde_json::json!({
                "id": STATUS_ID,
                "status": "complete",
                "total_count": 1,
                "success_count": 1,
                "failure_count": 0,
                "pending_count": 0,
                SERVER_CUSTOM: "The Server sends the Client a custom property."
            }),
        ))
        .mount(&server)
        .await;

    let client = interop_client(&server);
    let envelope = TaxiiEnvelope::new(vec![indicator_stix_object()]).with_custom(
        CLIENT_CUSTOM,
        serde_json::json!("The Client sends the Server a custom property."),
    );
    let status = client
        .add_objects(&api_root_url(&server), COL_WRITE_ONLY, &envelope)
        .await
        .expect("add with custom props");

    // TXC MUST continue processing and preserve unknown custom properties on the Status.
    assert_eq!(
        status.custom.get(SERVER_CUSTOM).and_then(|v| v.as_str()),
        Some("The Server sends the Client a custom property.")
    );
}
