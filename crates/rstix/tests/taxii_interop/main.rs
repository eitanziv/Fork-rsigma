//! OASIS TAXII 2.1 Interoperability — TXC (Table 51) suite.
//!
//! Authority: TAXII 2.1 Interoperability Test Document Version 1.0 CSD01 (2022-03-30).
//! Persona: TAXII Client (TXC). TXS is out of scope for this crate (client-only).
//! Channels (TAXII §6 RESERVED) are not part of Table 51.

mod harness;
mod scenarios;

use harness::manifest::load_manifest;

fn main() {
    // Install before any rustls ServerConfig/ClientConfig that relies on the
    // process default (mTLS mock TXS). Safe if already installed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    // Keep registry section order (do not sort by test_id string — `tc_3_10`
    // sorts before `tc_3_1_3` lexicographically).
    let tests = harness::registry::all_tests();
    for entry in tests {
        rt.block_on(async {
            (entry.run)().await;
        });
        harness::certification::record_outcome(
            entry.descriptor.req_id,
            harness::certification::Outcome::Pass,
        );
    }

    harness::certification::run_helper_self_tests();
    let manifest = load_manifest();
    harness::gate_expectations::maybe_write_gate_expectations_file(&manifest);
    harness::certification::finalize(&manifest);
}
