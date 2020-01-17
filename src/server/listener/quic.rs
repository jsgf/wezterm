use crate::server::pollable::{AsPollFd, ReadAndWrite};
use std::io::{Read, Write};

pub struct Quic {}

impl Read for Quic {}

impl Write for Quic {}

impl AsPollFd for Quic {}

impl ReadAndWrite for Quic {}
