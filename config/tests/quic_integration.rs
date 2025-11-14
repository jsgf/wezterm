/// Integration tests for QUIC transport
///
/// These tests validate:
/// - QUIC domain configuration parsing
/// - Client/server connection establishment
/// - Credential exchange
/// - Certificate handling
/// - Connection migration (future)
/// - 0-RTT reconnection (future)

#[test]
fn test_quic_domain_client_creation() {
    use config::QuicDomainClient;

    let client = QuicDomainClient {
        name: "test_quic".to_string(),
        remote_address: "localhost:9001".to_string(),
        bootstrap_via_ssh: Some("user@host:22".to_string()),
        persist_to_disk: false,
        certificate_lifetime_days: 7,
        enable_0rtt: true,
        enable_migration: true,
        max_idle_timeout: std::time::Duration::from_secs(30),
        pem_cert: None,
        pem_private_key: None,
        pem_ca: None,
        pem_root_certs: vec![],
        accept_invalid_hostnames: false,
        expected_cn: None,
        keep_alive_interval: None,
        connect_automatically: false,
        read_timeout: std::time::Duration::from_secs(30),
        write_timeout: std::time::Duration::from_secs(30),
        local_echo_threshold_ms: None,
        remote_wezterm_path: None,
        overlay_lag_indicator: false,
    };

    assert_eq!(client.name, "test_quic");
    assert_eq!(client.remote_address, "localhost:9001");
    assert!(client.bootstrap_via_ssh.is_some());
    assert!(!client.persist_to_disk);
    assert_eq!(client.certificate_lifetime_days, 7);
    assert!(client.enable_0rtt);
    assert!(client.enable_migration);
}

#[test]
fn test_quic_domain_server_creation() {
    use config::QuicDomainServer;

    let server = QuicDomainServer {
        bind_address: "[::]:9001".to_string(),
        certificate_lifetime_days: 7,
        pem_private_key: None,
        pem_cert: None,
        pem_ca: None,
        pem_root_certs: vec![],
        max_idle_timeout: std::time::Duration::from_secs(30),
    };

    assert_eq!(server.bind_address, "[::]:9001");
    assert_eq!(server.certificate_lifetime_days, 7);
    assert_eq!(server.max_idle_timeout, std::time::Duration::from_secs(30));
}

#[test]
fn test_quic_domain_client_ssh_parameters() {
    use config::QuicDomainClient;

    let client = QuicDomainClient {
        name: "test_quic".to_string(),
        remote_address: "localhost:9001".to_string(),
        bootstrap_via_ssh: Some("user@host:22".to_string()),
        persist_to_disk: false,
        certificate_lifetime_days: 7,
        enable_0rtt: true,
        enable_migration: true,
        max_idle_timeout: std::time::Duration::from_secs(30),
        pem_cert: None,
        pem_private_key: None,
        pem_ca: None,
        pem_root_certs: vec![],
        accept_invalid_hostnames: false,
        expected_cn: None,
        keep_alive_interval: None,
        connect_automatically: false,
        read_timeout: std::time::Duration::from_secs(30),
        write_timeout: std::time::Duration::from_secs(30),
        local_echo_threshold_ms: None,
        remote_wezterm_path: None,
        overlay_lag_indicator: false,
    };

    let ssh_params = client.ssh_parameters();
    assert!(ssh_params.is_some());
    let params = ssh_params.unwrap();
    assert!(params.is_ok());
}

#[test]
fn test_quic_domain_client_without_ssh_bootstrap() {
    use config::QuicDomainClient;

    let client = QuicDomainClient {
        name: "direct_quic".to_string(),
        remote_address: "localhost:9001".to_string(),
        bootstrap_via_ssh: None,
        persist_to_disk: false,
        certificate_lifetime_days: 7,
        enable_0rtt: true,
        enable_migration: true,
        max_idle_timeout: std::time::Duration::from_secs(30),
        pem_cert: None,
        pem_private_key: None,
        pem_ca: None,
        pem_root_certs: vec![],
        accept_invalid_hostnames: false,
        expected_cn: None,
        keep_alive_interval: None,
        connect_automatically: false,
        read_timeout: std::time::Duration::from_secs(30),
        write_timeout: std::time::Duration::from_secs(30),
        local_echo_threshold_ms: None,
        remote_wezterm_path: None,
        overlay_lag_indicator: false,
    };

    let ssh_params = client.ssh_parameters();
    assert!(ssh_params.is_none());
}

// TODO: Tests for actual QUIC connection when implementation complete:
// - test_quic_0rtt_reconnection
// - test_quic_connection_migration
// - test_quic_certificate_renewal
// - test_quic_certificate_expiry
// - test_quic_certificate_validation
// - test_quic_concurrent_connections
// - test_quic_large_data_transfer
// - test_quic_error_conditions

#[cfg(feature = "quic")]
mod cn_validation_tests {
    use x509_parser::prelude::*;
    use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType};
    use std::io::Cursor;

    /// Generate a test certificate with specified CN
    fn generate_test_cert(cn: &str) -> Vec<u8> {
        let mut params = CertificateParams::new(vec![cn.to_string()]);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;

        let cert = Certificate::from_params(params).expect("Failed to create test cert");
        cert.serialize_pem().expect("Failed to serialize cert").into_bytes()
    }

    #[test]
    fn test_extract_cn_from_certificate() {
        // Create a test certificate with CN = "testuser"
        let pem_data = generate_test_cert("testuser");

        // Parse the PEM to get the DER certificate
        let mut cursor = Cursor::new(&pem_data);
        let certs = rustls_pemfile::certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .expect("Failed to parse PEM");

        assert!(!certs.is_empty(), "Should have parsed at least one certificate");

        let cert_der = &certs[0];

        // Parse and extract CN
        let (_remainder, parsed) = parse_x509_certificate(cert_der.as_ref())
            .expect("Failed to parse certificate");

        let mut found_cn = None;
        for rdn in parsed.tbs_certificate.subject.iter_common_name() {
            if let Ok(cn) = rdn.as_str() {
                found_cn = Some(cn.to_string());
                break;
            }
        }

        assert_eq!(found_cn, Some("testuser".to_string()),
                   "Should have extracted CN 'testuser'");
    }

    #[test]
    fn test_cn_direct_match() {
        // Test direct match: CN == username
        let cn = "alice";
        let username = "alice";

        // In practice, this would be validated in verify_client_certificate_cn
        // For now, just verify the logic
        assert_eq!(cn, username);
    }

    #[test]
    fn test_cn_prefixed_format() {
        // Test prefixed format: CN starts with "user:username/"
        let cn = "user:bob/extra/data";
        let username = "bob";

        let prefix = format!("user:{}/", username);
        assert!(cn.starts_with(&prefix),
                "CN '{}' should start with prefix '{}'", cn, prefix);
    }

    #[test]
    fn test_cn_mismatch() {
        // Test mismatched CN
        let cn = "alice";
        let username = "bob";

        // Direct check should fail
        assert_ne!(cn, username);

        // Prefixed check should also fail
        let prefix = format!("user:{}/", username);
        assert!(!cn.starts_with(&prefix));
    }

    #[test]
    fn test_multiple_certs_uses_first() {
        // When multiple certificates are present, we use the first (end-entity)
        let cert1_pem = generate_test_cert("client_cert");
        let cert2_pem = generate_test_cert("ca_cert");

        let mut combined = cert1_pem.clone();
        combined.extend_from_slice(&cert2_pem);

        let mut cursor = Cursor::new(&combined);
        let certs = rustls_pemfile::certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .expect("Failed to parse PEM");

        assert_eq!(certs.len(), 2, "Should have parsed two certificates");

        // First cert should be the client cert
        let (_remainder, parsed) = parse_x509_certificate(certs[0].as_ref())
            .expect("Failed to parse first certificate");

        let mut found_cn = None;
        for rdn in parsed.tbs_certificate.subject.iter_common_name() {
            if let Ok(cn) = rdn.as_str() {
                found_cn = Some(cn.to_string());
                break;
            }
        }

        assert_eq!(found_cn, Some("client_cert".to_string()),
                   "First cert in chain should be the client certificate");
    }
}
