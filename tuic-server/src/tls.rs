use std::{
    ops::Deref,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use eyre::{Context, Result};
use notify::{RecursiveMode, Watcher as _};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use tracing::{debug, warn};

use crate::utils;

#[derive(Debug)]
pub struct CertResolver {
    cert_path: PathBuf,
    key_path: PathBuf,
    cert_key: RwLock<Arc<CertifiedKey>>,
}
impl CertResolver {
    pub async fn new(cert_path: &Path, key_path: &Path) -> Result<Arc<Self>> {
        let cert_key = load_cert_key(cert_path, key_path).await?;
        let resolver = Arc::new(Self {
            cert_path: cert_path.to_owned(),
            key_path: key_path.to_owned(),
            cert_key: RwLock::new(cert_key),
        });
        // Start file watcher in background
        let resolver_clone = resolver.clone();
        tokio::spawn(async move {
            if let Err(e) = resolver_clone.start_watch().await {
                warn!("Certificate watcher exited with error: {e}");
            }
        });
        Ok(resolver)
    }

    async fn start_watch(&self) -> Result<()> {
        let (mut watcher, mut rx) = utils::async_watcher().await?;

        watcher.watch(&self.cert_path, RecursiveMode::NonRecursive)?;
        watcher.watch(&self.key_path, RecursiveMode::NonRecursive)?;
        loop {
            let res = rx.recv().await;
            match res {
                Ok(_) => {}
                Err(e) => {
                    warn!("File watcher error: {e}");
                    break;
                }
            };
            debug!("File system event received");
            match self.reload_cert_key().await {
                Ok(_) => warn!("Successfully reloaded TLS certificate and key"),
                Err(e) => warn!("Failed to reload TLS certificate and key: {e}"),
            }
        }

        Ok(())
    }

    async fn reload_cert_key(&self) -> Result<()> {
        let new_cert_key = load_cert_key(&self.cert_path, &self.key_path).await?;
        let mut guard = self
            .cert_key
            .write()
            .map_err(|_| eyre::eyre!("Certificate lock poisoned"))?;
        *guard = new_cert_key;
        Ok(())
    }
}
impl ResolvesServerCert for CertResolver {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.cert_key.read().map(|guard| guard.deref().clone()).ok()
    }
}

async fn load_cert_key(cert_path: &Path, key_path: &Path) -> eyre::Result<Arc<CertifiedKey>> {
    let (cert_chain, der) = tokio::join!(load_cert_chain(cert_path), load_priv_key(key_path),);
    let cert_chain = cert_chain?;
    let der = der?;
    #[cfg(feature = "aws-lc-rs")]
    let key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&der)
        .context("Unsupported private key type")?;
    #[cfg(feature = "ring")]
    let key = rustls::crypto::ring::sign::any_supported_type(&der)
        .context("Unsupported private key type")?;

    Ok(Arc::new(CertifiedKey::new(cert_chain, key)))
}

async fn load_cert_chain(cert_path: &Path) -> eyre::Result<Vec<CertificateDer<'static>>> {
    let data = tokio::fs::read(cert_path)
        .await
        .context("Failed to read certificate chain")?;

    if cert_path.extension().is_some_and(|ext| ext == "der") {
        Ok(vec![CertificateDer::from(data)])
    } else {
        rustls_pemfile::certs(&mut data.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .context("Invalid PEM certificate(s)")
    }
}

async fn load_priv_key(key_path: &Path) -> eyre::Result<PrivateKeyDer<'static>> {
    let data = tokio::fs::read(key_path)
        .await
        .context("Failed to read private key")?;

    if key_path.extension().is_some_and(|ext| ext == "der") {
        Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(data)))
    } else {
        rustls_pemfile::private_key(&mut data.as_slice())
            .context("Malformed PEM private key")?
            .ok_or_else(|| eyre::eyre!("No private keys found in file"))
    }
}
