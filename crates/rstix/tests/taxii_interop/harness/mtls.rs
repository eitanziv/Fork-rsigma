//! Local rustls mTLS acceptor for TXC §3.1.3 (certificate-based authentication).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rstix::taxii::{
    ClientCertificate, ServerTrustPolicy, SpkiPin, TaxiiClient, TaxiiClientConfig, TlsaCache,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_webpki::EndEntityCert;
use sha2::{Digest, Sha256};

fn live_cert_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/taxii-live/fixtures/certs")
}

fn read_pem(name: &str) -> Vec<u8> {
    let path = live_cert_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

fn spki_pin(cert: &CertificateDer<'_>) -> SpkiPin {
    let ee = EndEntityCert::try_from(cert).expect("end-entity cert");
    let hash = Sha256::digest(ee.subject_public_key_info());
    let mut hex = String::with_capacity(64);
    for byte in hash {
        hex.push_str(&format!("{byte:02x}"));
    }
    SpkiPin::from_hex(&hex).expect("spki pin")
}

/// Serve one HTTPS discovery response that requires a client certificate (CSD01 §3.1.3).
pub async fn certificate_auth() {
    let ca_pem = read_pem("ca.pem");
    let server_pem = read_pem("server.pem");
    let server_key = read_pem("server-key.pem");
    let client_pem = read_pem("client.pem");
    let client_key = read_pem("client-key.pem");

    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&ca_pem) {
        roots
            .add(cert.expect("ca cert"))
            .expect("add ca to root store");
    }
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .expect("client verifier");

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&server_pem)
        .map(|c| c.expect("server cert"))
        .collect();
    let key = PrivateKeyDer::from_pem_slice(&server_key).expect("server key");
    let pin = spki_pin(&certs[0]);

    let server_config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, key)
        .expect("server config");
    let server_config = Arc::new(server_config);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let body = br#"{"title":"TAXII Server Under Test","api_roots":["/api1/"]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/taxii+json;version=2.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        std::str::from_utf8(body).unwrap()
    );

    let accept = thread::spawn(move || {
        let (mut tcp, _) = listener.accept().expect("accept");
        tcp.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        tcp.set_write_timeout(Some(Duration::from_secs(5)))
            .expect("write timeout");
        let mut conn = rustls::ServerConnection::new(server_config).expect("server conn");
        let mut stream = rustls::Stream::new(&mut conn, &mut tcp);
        let mut req = [0u8; 4096];
        let _ = stream.read(&mut req);
        stream.write_all(response.as_bytes()).expect("write");
        let _ = stream.flush();
    });

    let client_cert =
        ClientCertificate::from_pem(&client_pem, &client_key).expect("client certificate");
    let client = TaxiiClient::new(
        TaxiiClientConfig::new(format!("https://127.0.0.1:{}/", addr.port()))
            .client_certificate(client_cert)
            .server_trust(ServerTrustPolicy::PinnedSpkiOnly(vec![pin]))
            .tlsa_cache(TlsaCache::default())
            .timeout(Duration::from_secs(5)),
    )
    .expect("mtls client");

    let discovery = client.discover().await.expect("discover with client cert");
    assert_eq!(discovery.title, "TAXII Server Under Test");
    assert!(!discovery.api_roots.is_empty());

    accept.join().expect("server thread");
}
