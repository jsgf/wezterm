use anyhow::{anyhow, Context, Error};
use async_ossl::AsyncSslStream;
use config::TlsDomainServer;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslStream, SslVerifyMode};
use openssl::x509::X509;
use promise::spawn::spawn_into_main_thread;
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use wezterm_mux_server_impl::PKI;

struct OpenSSLNetListener {
    acceptor: Arc<SslAcceptor>,
    listener: TcpListener,
}

impl OpenSSLNetListener {
    pub fn new(listener: TcpListener, acceptor: SslAcceptor) -> Self {
        Self {
            listener,
            acceptor: Arc::new(acceptor),
        }
    }

    /// Authenticates the peer.
    /// The requirements are:
    /// * The peer must have a certificate
    /// * The peer certificate must be trusted
    /// * The peer certificate must include a CN string that is
    ///   either an exact match for the unix username of the
    ///   user running this mux server instance, or must match
    ///   a special encoded prefix set up by a proprietary PKI
    ///   infrastructure in an environment used by the author.
    fn verify_peer_cert<T>(stream: &SslStream<T>) -> anyhow::Result<()> {
        let cert = stream
            .ssl()
            .peer_certificate()
            .ok_or_else(|| anyhow!("no peer cert"))?;
        let subject = cert.subject_name();
        let cn = subject
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .ok_or_else(|| anyhow!("cert has no CN"))?;
        let cn_str = cn.data().as_utf8()?.to_string();

        let wanted_unix_name = std::env::var("USER")?;

        if wanted_unix_name == cn_str {
            log::trace!(
                "Peer certificate CN `{}` == $USER `{}`",
                cn_str,
                wanted_unix_name
            );
            Ok(())
        } else {
            // Some environments that are used by the author of this
            // program encode the CN in the form `user:unixname/DATA`
            let maybe_encoded = format!("user:{}/", wanted_unix_name);
            if cn_str.starts_with(&maybe_encoded) {
                log::trace!(
                    "Peer certificate CN `{}` matches $USER `{}`",
                    cn_str,
                    wanted_unix_name
                );
                Ok(())
            } else {
                anyhow::bail!("CN `{}` did not match $USER `{}`", cn_str, wanted_unix_name);
            }
        }
    }

    fn run(&mut self) {
        for stream in self.listener.incoming() {
            match stream {
                Ok(stream) => {
                    stream.set_nodelay(true).ok();
                    let acceptor = self.acceptor.clone();

                    match acceptor.accept(stream) {
                        Ok(stream) => {
                            if let Err(err) = Self::verify_peer_cert(&stream) {
                                log::error!("problem with peer cert: {}", err);
                                break;
                            }
                            spawn_into_main_thread(async move {
                                log::error!("Making new AsyncSslStream");
                                wezterm_mux_server_impl::dispatch::process(AsyncSslStream::new(
                                    stream,
                                ))
                                .await
                                .map_err(|e| {
                                    log::error!("process: {:?}", e);
                                    e
                                })
                            })
                            .detach();
                        }
                        Err(e) => {
                            log::error!("failed TlsAcceptor: {}", e);
                        }
                    }
                }
                Err(err) => {
                    log::error!("accept failed: {}", err);
                    return;
                }
            }
        }
    }
}

pub fn spawn_tls_listener(tls_server: &TlsDomainServer) -> Result<(), Error> {
    openssl::init();

    let mut acceptor = SslAcceptor::mozilla_modern(SslMethod::tls())?;

    // Handle certificate and key based on configuration or generate ephemeral cert
    if let Some(cert_file) = &tls_server.pem_cert {
        // Explicit certificate file provided
        acceptor
            .set_certificate_file(cert_file, SslFiletype::PEM)
            .context(format!(
                "set_certificate_file to {} for TLS listener",
                cert_file.display()
            ))?;

        let key_file = tls_server
            .pem_private_key
            .clone()
            .ok_or_else(|| anyhow!("pem_cert requires pem_private_key to be configured"))?;
        acceptor
            .set_private_key_file(&key_file, SslFiletype::PEM)
            .context(format!(
                "set_private_key_file to {} for TLS listener",
                key_file.display()
            ))?;
    } else {
        // Generate ephemeral server certificate like QUIC does
        log::info!(
            "TLS: Generating ephemeral server certificate for listener on {}",
            tls_server.bind_address
        );

        let extra_san = if tls_server.extra_san.is_empty() {
            None
        } else {
            log::info!("TLS: Adding extra SANs to certificate: {:?}", tls_server.extra_san);
            Some(tls_server.extra_san.clone())
        };

        let cert_pem = PKI
            .generate_server_cert(365, extra_san)
            .context("Failed to generate server certificate")?;

        // Write cert+key to temporary file for loading by OpenSSL
        let temp_cert = std::env::temp_dir().join(format!(
            "wezterm-tls-ephemeral-{}.pem",
            std::process::id()
        ));
        std::fs::write(&temp_cert, &cert_pem)
            .context("Failed to write ephemeral certificate to temp file")?;

        acceptor
            .set_certificate_file(&temp_cert, SslFiletype::PEM)
            .context("Failed to set generated certificate from temp file")?;

        // The PEM file contains both cert and private key, so we can use the same file
        acceptor
            .set_private_key_file(&temp_cert, SslFiletype::PEM)
            .context("Failed to set generated private key from temp file")?;
    }

    if let Some(chain_file) = tls_server.pem_ca.as_ref() {
        acceptor
            .set_certificate_chain_file(&chain_file)
            .context(format!(
                "set_certificate_chain_file to {} for TLS listener",
                chain_file.display()
            ))?;
    }

    fn load_cert(name: &Path) -> anyhow::Result<X509> {
        let cert_bytes = std::fs::read(name)?;
        log::trace!("loaded {}", name.display());
        Ok(X509::from_pem(&cert_bytes)?)
    }
    for name in &tls_server.pem_root_certs {
        if name.is_dir() {
            for entry in std::fs::read_dir(name)? {
                if let Ok(cert) = load_cert(&entry?.path()) {
                    acceptor.cert_store_mut().add_cert(cert).ok();
                }
            }
        } else {
            acceptor.cert_store_mut().add_cert(load_cert(name)?)?;
        }
    }

    acceptor
        .cert_store_mut()
        .add_cert(X509::from_pem(PKI.ca_pem_string_cached().as_bytes())?)?;

    acceptor.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);

    let acceptor = acceptor.build();

    log::error!("listening with TLS on {:?}", tls_server.bind_address);

    let mut net_listener = OpenSSLNetListener::new(
        TcpListener::bind(&tls_server.bind_address).with_context(|| {
            format!(
                "error binding to mux_server_bind_address {}",
                tls_server.bind_address,
            )
        })?,
        acceptor,
    );
    std::thread::spawn(move || {
        net_listener.run();
    });
    Ok(())
}
