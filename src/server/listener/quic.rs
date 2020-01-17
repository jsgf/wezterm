use super::*;
use crate::config::QuicDomainServer;
use crate::server::pollable::{AsPollFd, ReadAndWrite};
use filedescriptor::*;
use std::io::{self, Read, Write};
use std::time::Duration;

pub struct Quic {}

impl Read for Quic {
    fn read(&mut self, _buf: &mut [u8]) -> Result<usize, io::Error> {
        unimplemented!()
    }
}

impl Write for Quic {
    fn write(&mut self, _buf: &[u8]) -> Result<usize, io::Error> {
        unimplemented!()
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        unimplemented!()
    }
}

impl AsPollFd for Quic {
    fn as_poll_fd(&self) -> pollfd {
        unimplemented!()
    }
}

impl ReadAndWrite for Quic {
    fn set_non_blocking(&self, _non_blocking: bool) -> anyhow::Result<()> {
        unimplemented!()
    }

    fn has_read_buffered(&self) -> bool {
        unimplemented!()
    }

    fn timeout(&self) -> Option<Duration> {
        unimplemented!()
    }

    fn on_timeout(&self) {
        unimplemented!()
    }
}

pub fn spawn_quic_listener(quic_server: &QuicDomainServer) -> Result<(), Error> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;

    if let Some(pem_cert) = &quic_server.certs.pem_cert {
        config.load_cert_chain_from_pem_file(pem_cert.to_str().unwrap())?;
    }
    if let Some(pem_priv) = &quic_server.certs.pem_private_key {
        config.load_priv_key_from_pem_file(pem_priv.to_str().unwrap())?;
    }

    config.set_application_protos(b"\x07wezterm")?;

    unimplemented!()
}
