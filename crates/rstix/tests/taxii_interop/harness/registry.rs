//! Compile-time TXC scenario registry (explicit Table 51 mapping).

use std::future::Future;
use std::pin::Pin;

pub type TxcFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

#[derive(Clone, Copy)]
pub struct TestDescriptor {
    pub req_id: &'static str,
    pub test_id: &'static str,
}

pub struct TxcTestEntry {
    pub descriptor: TestDescriptor,
    pub run: fn() -> TxcFuture,
}

macro_rules! entry {
    ($req_id:expr, $test_id:expr, $func:path) => {
        TxcTestEntry {
            descriptor: TestDescriptor {
                req_id: $req_id,
                test_id: $test_id,
            },
            run: || Box::pin($func()),
        }
    };
}

/// All Mandatory Table 51 scenarios (order = section order).
pub fn all_tests() -> Vec<TxcTestEntry> {
    use crate::scenarios::{
        auth, collections, custom, discovery, filters, objects, pagination, status,
    };

    vec![
        entry!(
            "REQ-TXC-3.1.1",
            "tc_3_1_1_missing_authorization",
            auth::missing_authorization
        ),
        entry!(
            "REQ-TXC-3.1.2",
            "tc_3_1_2_authorization_error",
            auth::authorization_error
        ),
        entry!(
            "REQ-TXC-3.1.3",
            "tc_3_1_3_certificate_auth",
            auth::certificate_auth
        ),
        entry!("REQ-TXC-3.1.4", "tc_3_1_4_http_basic", auth::http_basic),
        entry!(
            "REQ-TXC-3.2.1",
            "tc_3_2_1_get_discovery",
            discovery::get_discovery
        ),
        entry!(
            "REQ-TXC-3.3.1",
            "tc_3_3_1_get_api_root",
            discovery::get_api_root
        ),
        entry!(
            "REQ-TXC-3.3.2",
            "tc_3_3_2_incorrect_api_root",
            discovery::incorrect_api_root
        ),
        entry!(
            "REQ-TXC-3.4.1",
            "tc_3_4_1_get_collections",
            collections::get_collections
        ),
        entry!(
            "REQ-TXC-3.5.1.1",
            "tc_3_5_1_1_write_only_collection",
            collections::write_only_collection
        ),
        entry!(
            "REQ-TXC-3.5.1.2",
            "tc_3_5_1_2_read_write_collection",
            collections::read_write_collection
        ),
        entry!(
            "REQ-TXC-3.5.1.3",
            "tc_3_5_1_3_read_only_collection",
            collections::read_only_collection
        ),
        entry!(
            "REQ-TXC-3.5.1.4",
            "tc_3_5_1_4_no_read_no_write_collection",
            collections::no_read_no_write_collection
        ),
        entry!(
            "REQ-TXC-3.5.2.1",
            "tc_3_5_2_1_read_write_only_forbidden",
            collections::read_write_only_forbidden
        ),
        entry!(
            "REQ-TXC-3.5.2.2",
            "tc_3_5_2_2_write_read_only_forbidden",
            collections::write_read_only_forbidden
        ),
        entry!(
            "REQ-TXC-3.5.2.3",
            "tc_3_5_2_3_delete_forbidden",
            collections::delete_forbidden
        ),
        entry!(
            "REQ-TXC-3.5.2.4",
            "tc_3_5_2_4_delete_not_found",
            collections::delete_not_found
        ),
        entry!(
            "REQ-TXC-3.5.3",
            "tc_3_5_3_incorrect_collection",
            collections::incorrect_collection
        ),
        entry!(
            "REQ-TXC-3.6.1",
            "tc_3_6_1_get_manifest",
            objects::get_manifest
        ),
        entry!(
            "REQ-TXC-3.7.1",
            "tc_3_7_1_get_objects",
            objects::get_objects
        ),
        entry!("REQ-TXC-3.7.2", "tc_3_7_2_no_objects", objects::no_objects),
        entry!("REQ-TXC-3.8.1", "tc_3_8_1_get_object", objects::get_object),
        entry!(
            "REQ-TXC-3.8.2",
            "tc_3_8_2_object_not_found",
            objects::object_not_found
        ),
        entry!(
            "REQ-TXC-3.9.1",
            "tc_3_9_1_get_versions",
            objects::get_versions
        ),
        entry!(
            "REQ-TXC-3.10.1",
            "tc_3_10_1_add_objects",
            objects::add_objects
        ),
        entry!("REQ-TXC-3.11.1", "tc_3_11_1_get_status", status::get_status),
        entry!(
            "REQ-TXC-3.11.2",
            "tc_3_11_2_get_all_status_properties",
            status::get_all_status_properties
        ),
        entry!(
            "REQ-TXC-3.12.1",
            "tc_3_12_1_delete_object",
            objects::delete_object
        ),
        entry!(
            "REQ-TXC-3.13.1.1",
            "tc_3_13_1_1_added_after",
            filters::added_after
        ),
        entry!("REQ-TXC-3.13.1.2", "tc_3_13_1_2_limit", filters::limit),
        entry!(
            "REQ-TXC-3.13.1.3",
            "tc_3_13_1_3_match_id",
            filters::match_id
        ),
        entry!(
            "REQ-TXC-3.13.1.4",
            "tc_3_13_1_4_match_type",
            filters::match_type
        ),
        entry!(
            "REQ-TXC-3.13.1.5",
            "tc_3_13_1_5_match_version",
            filters::match_version
        ),
        entry!(
            "REQ-TXC-3.13.1.6",
            "tc_3_13_1_6_match_spec_version",
            filters::match_spec_version
        ),
        entry!(
            "REQ-TXC-3.13.1.7",
            "tc_3_13_1_7_logical_or",
            filters::logical_or
        ),
        entry!(
            "REQ-TXC-3.13.1.8",
            "tc_3_13_1_8_logical_and",
            filters::logical_and
        ),
        entry!(
            "REQ-TXC-3.13.1.9",
            "tc_3_13_1_9_logical_or_and",
            filters::logical_or_and
        ),
        entry!(
            "REQ-TXC-3.13.1.10",
            "tc_3_13_1_10_duplicate_filter",
            filters::duplicate_filter
        ),
        entry!(
            "REQ-TXC-3.14.1",
            "tc_3_14_1_pagination",
            pagination::pagination
        ),
        entry!(
            "REQ-TXC-3.15.1",
            "tc_3_15_1_custom_properties",
            custom::custom_properties
        ),
    ]
}
