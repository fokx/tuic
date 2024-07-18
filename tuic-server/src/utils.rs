use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    fs::{self, File},
    io::{BufReader, Error as IoError},
    path::PathBuf,
    str::FromStr,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::Item;

pub fn load_certs(path: PathBuf) -> Result<Vec<CertificateDer<'static>>, IoError> {
    let mut file = BufReader::new(File::open(&path)?);
    let mut certs = Vec::new();

    while let Ok(Some(item)) = rustls_pemfile::read_one(&mut file) {
        if let Item::X509Certificate(cert) = item {
            certs.push(CertificateDer::from(cert));
        }
    }

    if certs.is_empty() {
        certs = vec![CertificateDer::from(fs::read(&path)?)];
    }

    Ok(certs)
}

pub fn load_priv_key(path: PathBuf) -> Result<PrivateKeyDer<'static>, IoError> {
    let mut file = BufReader::new(File::open(&path)?);
    let mut priv_key = None;

    // while let Ok(Some(item)) = rustls_pemfile::read_one(&mut file) {
    //     if let Item::Pkcs1Key(key) | Item::Pkcs8Key(key) | Item::Sec1Key(key) = item {
    //         priv_key = Some(PrivateKeyDer::from(key));
    //     }
    // }

    for item in std::iter::from_fn(|| rustls_pemfile::read_one(&mut file).transpose()) {
        match item.unwrap() {
            Item::Pkcs1Key(key) => priv_key=Some(PrivateKeyDer::from(key)),
            Item::Pkcs8Key(key) => priv_key=Some(PrivateKeyDer::from(key)),
            Item::Sec1Key(key) => priv_key=Some(PrivateKeyDer::from(key)),
            _ => {},
        }
    }
    priv_key.ok_or(IoError::new(std::io::ErrorKind::InvalidData, "failed to load private key"))
    // if priv_key.is_none() {
    //         priv_key = PrivateKeyDer::try_from(fs::read(&path)).ok();
    // }
    // priv_key.ok_or("failed to load private key")
}

#[derive(Clone, Copy)]
pub enum UdpRelayMode {
    Native,
    Quic,
}

impl Display for UdpRelayMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Native => write!(f, "native"),
            Self::Quic => write!(f, "quic"),
        }
    }
}

pub enum CongestionControl {
    Cubic,
    NewReno,
    Bbr,
}

impl FromStr for CongestionControl {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("cubic") {
            Ok(Self::Cubic)
        } else if s.eq_ignore_ascii_case("new_reno") || s.eq_ignore_ascii_case("newreno") {
            Ok(Self::NewReno)
        } else if s.eq_ignore_ascii_case("bbr") {
            Ok(Self::Bbr)
        } else {
            Err("invalid congestion control")
        }
    }
}
