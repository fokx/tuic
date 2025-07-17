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

    let pem_result = rustls_pemfile::certs(&mut data.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .context("Invalid PEM certificate(s)");

    match pem_result {
        Ok(certs) if !certs.is_empty() => Ok(certs),
        _ => {
            if data.is_empty() {
                return Err(eyre::eyre!("Empty certificate file"));
            }
            Ok(vec![CertificateDer::from(data)])
        }
    }
}

async fn load_priv_key(key_path: &Path) -> eyre::Result<PrivateKeyDer<'static>> {
    let data = tokio::fs::read(key_path)
        .await
        .context("Failed to read private key")?;

    // 尝试解析为PEM格式
    if let Ok(Some(key)) =
        rustls_pemfile::private_key(&mut data.as_slice()).context("Malformed PEM private key")
    {
        return Ok(key);
    }

    // 所有PEM解析失败，尝试DER格式
    if data.is_empty() {
        return Err(eyre::eyre!("Empty private key file"));
    }
    // 假设DER格式是PKCS#8
    Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(data)))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use rcgen::{CertificateParams, DnType, Ia5String, KeyPair, SanType};
    use tempfile::{NamedTempFile, tempdir};
    use tokio::time::{Duration, sleep};

    use super::*;

    // 生成测试证书和私钥
    fn generate_test_cert() -> eyre::Result<(String, String)> {
        let mut params = CertificateParams::default();

        // 设置主题可分辨名称（DN）
        let mut distinguished_name = rcgen::DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, "localhost");
        distinguished_name.push(DnType::OrganizationName, "My Company");
        distinguished_name.push(DnType::CountryName, "US");
        params.distinguished_name = distinguished_name;

        // 添加 SAN（主题备用名称）
        params.subject_alt_names = vec![
            SanType::DnsName(Ia5String::try_from("localhost".to_string())?),
            SanType::IpAddress("127.0.0.1".parse()?),
        ];
        let key_pair = KeyPair::generate()?;
        key_pair.serialize_der();
        // 生成密钥对和证书
        let cert = params.self_signed(&key_pair)?;

        // 获取PEM格式的私钥
        let private_key_pem = key_pair.serialize_pem();

        // 获取PEM格式的证书
        let cert_pem = cert.pem();

        Ok((cert_pem, private_key_pem))
    }

    // 生成测试证书和私钥
    fn generate_test_cert_der() -> eyre::Result<(Vec<u8>, Vec<u8>)> {
        let mut params = CertificateParams::default();

        // 设置主题可分辨名称（DN）
        let mut distinguished_name = rcgen::DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, "localhost");
        distinguished_name.push(DnType::OrganizationName, "My Company");
        distinguished_name.push(DnType::CountryName, "US");
        params.distinguished_name = distinguished_name;

        // 添加 SAN（主题备用名称）
        params.subject_alt_names = vec![
            SanType::DnsName(Ia5String::try_from("localhost".to_string())?),
            SanType::IpAddress("127.0.0.1".parse()?),
        ];
        let key_pair = KeyPair::generate()?;

        let cert = params.self_signed(&key_pair)?;

        let private_key_der = key_pair.serialize_der();

        let cert_der = cert.der();

        Ok((cert_der.to_vec(), private_key_der))
    }

    // 创建临时证书文件
    async fn create_temp_cert_file(
        cert_data: &[u8],
        key_data: &[u8],
        cert_ext: &str,
        key_ext: &str,
    ) -> (NamedTempFile, NamedTempFile) {
        // 创建证书文件
        let mut cert_file = NamedTempFile::new().unwrap();
        let cert_path = cert_file.path().with_extension(cert_ext);
        cert_file = NamedTempFile::new_in(cert_path.parent().unwrap()).unwrap();
        cert_file.write_all(cert_data).unwrap();
        cert_file.as_file().sync_all().unwrap();

        // 创建私钥文件
        let mut key_file = NamedTempFile::new().unwrap();
        let key_path = key_file.path().with_extension(key_ext);
        key_file = NamedTempFile::new_in(key_path.parent().unwrap()).unwrap();
        key_file.write_all(key_data).unwrap();
        key_file.as_file().sync_all().unwrap();
        dbg!(key_file.as_file());
        (cert_file, key_file)
    }

    #[tokio::test]
    async fn test_load_cert_chain_pem() -> Result<()> {
        let (cert_pem, _) = generate_test_cert()?;
        let (cert_file, _) = create_temp_cert_file(cert_pem.as_bytes(), b"", "pem", "").await;

        let result = load_cert_chain(cert_file.path()).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn test_load_cert_chain_der() -> Result<()> {
        let (cert_der, _) = generate_test_cert_der()?;

        let (cert_file, _) = create_temp_cert_file(&cert_der, b"", "der", "").await;

        let result = load_cert_chain(cert_file.path()).await?;
        assert_eq!(result.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn test_load_priv_key_pem() -> Result<()> {
        let (_, key_pem) = generate_test_cert()?;
        let (_, key_file) = create_temp_cert_file(b"", key_pem.as_bytes(), "", "pem").await;

        let result = load_priv_key(key_file.path()).await;
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_load_priv_key_der() -> Result<()> {
        let (_, key_der) = generate_test_cert_der()?;

        let (_, key_file) = create_temp_cert_file(b"", &key_der, "", "der").await;

        let result = load_priv_key(key_file.path()).await;
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_cert_resolver_initial_load() -> Result<()> {
        let (cert_der, key_der) = generate_test_cert_der()?;
        let (cert_file, key_file) = create_temp_cert_file(&cert_der, &key_der, "der", "der").await;

        let resolver = CertResolver::new(cert_file.path(), key_file.path())
            .await
            .unwrap();

        // 验证初始证书加载
        let certified_key = resolver.cert_key.read().unwrap();
        assert!(!certified_key.cert.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_cert_resolver_reload() -> Result<()> {
        let temp_dir = tempdir().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        // 初始文件
        let (cert_pem, key_pem) = generate_test_cert()?;
        tokio::fs::write(&cert_path, &cert_pem.as_bytes())
            .await
            .unwrap();
        tokio::fs::write(&key_path, &key_pem.as_bytes())
            .await
            .unwrap();

        let resolver = CertResolver::new(&cert_path, &key_path).await.unwrap();

        // 获取初始指纹
        let initial_fingerprint = {
            let key = resolver.cert_key.read().unwrap();
            key.cert[0].as_ref().to_vec()
        };

        // 生成新证书并覆盖文件
        let (new_cert_pem, new_key_pem) = generate_test_cert()?;
        tokio::fs::write(&cert_path, &new_cert_pem).await.unwrap();
        tokio::fs::write(&key_path, &new_key_pem).await.unwrap();

        // 等待文件系统事件处理
        sleep(Duration::from_millis(500)).await;

        // 验证证书已更新
        let updated_fingerprint = {
            let key = resolver.cert_key.read().unwrap();
            key.cert[0].as_ref().to_vec()
        };

        assert_ne!(initial_fingerprint, updated_fingerprint);
        Ok(())
    }

    // #[tokio::test]
    // async fn test_resolves_server_cert() {
    //     let (cert_pem, key_pem) = generate_test_cert();
    //     let (cert_file, key_file) = create_temp_cert_file(&cert_pem, &key_pem,
    // "pem", "pem").await;

    //     let resolver = CertResolver::new(cert_file.path(), key_file.path())
    //         .await
    //         .unwrap();

    //     // 模拟ClientHello
    //     struct MockClientHello;
    //     impl ClientHello<'_> for MockClientHello {
    //         fn server_name(&self) -> Option<&str> {
    //             None
    //         }

    //         fn signature_schemes(&self) -> &[rustls::SignatureScheme] {
    //             &[]
    //         }

    //         fn alpn(&self) -> Option<&[&[u8]]> {
    //             None
    //         }

    //         fn cipher_suites(&self) -> &[rustls::SupportedCipherSuite] {
    //             &[]
    //         }
    //     }

    //     let certified_key = resolver.resolve(MockClientHello);
    //     assert!(certified_key.is_some());
    //     assert!(!certified_key.unwrap().cert().is_empty());
    // }

    #[tokio::test]
    async fn test_invalid_cert_handling() {
        let (cert_file, key_file) =
            create_temp_cert_file(b"invalid", b"invalid", "pem", "pem").await;

        // 初始加载应失败
        let load_result = load_cert_key(cert_file.path(), key_file.path()).await;
        assert!(load_result.is_err());

        // 解析器初始化应失败
        let resolver_result = CertResolver::new(cert_file.path(), key_file.path()).await;
        assert!(resolver_result.is_err());
    }
}
