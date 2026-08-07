//! Local rustls mTLS acceptor for TXC §3.1.3 (certificate-based authentication).
//!
//! Certificates are minted in-process with `rcgen` so the suite does not depend
//! on gitignored `taxii-live` PEMs (those remain for the optional live harness).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rcgen::{
    CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use rstix::taxii::{
    ClientCertificate, ServerTrustPolicy, SpkiPin, TaxiiClient, TaxiiClientConfig, TlsaCache,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_webpki::EndEntityCert;
use sha2::{Digest, Sha256};

struct MtlsMaterial {
    ca_pem: String,
    server_pem: String,
    server_key_pem: String,
    client_pem: String,
    client_key_pem: String,
}

fn mint_mtls_material() -> MtlsMaterial {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "rstix-taxii-interop-ca");
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_key = KeyPair::generate().expect("ca key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
    let ca_pem = ca_cert.pem();
    let ca_issuer = Issuer::new(ca_params, ca_key);

    let mut server_params =
        CertificateParams::new(vec!["localhost".to_string()]).expect("server params");
    server_params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(std::net::IpAddr::from([
            127, 0, 0, 1,
        ])));
    server_params
        .distinguished_name
        .push(DnType::CommonName, "rstix-taxii-interop-server");
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = KeyPair::generate().expect("server key");
    let server_cert = server_params
        .signed_by(&server_key, &ca_issuer)
        .expect("server cert");

    let mut client_params = CertificateParams::new(Vec::<String>::new()).expect("client params");
    client_params
        .distinguished_name
        .push(DnType::CommonName, "rstix-taxii-interop-client");
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_key = KeyPair::generate().expect("client key");
    let client_cert = client_params
        .signed_by(&client_key, &ca_issuer)
        .expect("client cert");

    MtlsMaterial {
        ca_pem,
        server_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        client_pem: client_cert.pem(),
        client_key_pem: client_key.serialize_pem(),
    }
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

fn install_ring_provider() {
    // reqwest's rustls feature may also enable aws-lc-rs; with both linked,
    // rustls refuses to auto-select a process default. Pin ring (same as
    // `build_rustls_config` in the TAXII client).
    let provider = rustls::crypto::ring::default_provider();
    let _ = provider.install_default();
}

/// Serve one HTTPS discovery response that requires a client certificate (CSD01 §3.1.3).
pub async fn certificate_auth() {
    install_ring_provider();

    let material = mint_mtls_material();
    let ca_pem = material.ca_pem.into_bytes();
    let server_pem = material.server_pem.into_bytes();
    let server_key = material.server_key_pem.into_bytes();
    let client_pem = material.client_pem.into_bytes();
    let client_key = material.client_key_pem.into_bytes();

    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&ca_pem) {
        roots
            .add(cert.expect("ca cert"))
            .expect("add ca to root store");
    }
    let client_verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .expect("client verifier");

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&server_pem)
        .map(|c| c.expect("server cert"))
        .collect();
    let key = PrivateKeyDer::from_pem_slice(&server_key).expect("server key");
    let pin = spki_pin(&certs[0]);

    let server_config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("tls versions")
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
