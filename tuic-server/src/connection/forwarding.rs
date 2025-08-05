use std::{
    collections::HashMap,
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    sync::{Arc, Weak, atomic::AtomicU32},
    time::Duration,
};

use eyre::{Context, eyre};
use arc_swap::ArcSwap;
use quinn::{
    ClientConfig, Connection as QuinnConnection, Endpoint as QuinnEndpoint, EndpointConfig,
    TokioRuntime, TransportConfig, VarInt,
    congestion::{BbrConfig, CubicConfig, NewRenoConfig},
    crypto::rustls::QuicClientConfig,
};
use register_count::Counter;
use rustls::{
    ClientConfig as RustlsClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use tokio::{sync::RwLock as AsyncRwLock, time, net};
use tracing::{debug, info, warn};
use tuic_quinn::{Authenticate, Connection as Model, side};
use uuid::Uuid;

use crate::{AppContext, config::ForwardingConfig, error::Error, utils::{CongestionController, UdpRelayMode}, connection::ERROR_CODE};

/// Manages connection to exit server for forwarding traffic
#[derive(Clone)]
pub struct ForwardingConnection {
    ctx: Arc<AppContext>,
    inner: QuinnConnection,
    model: Model<side::Client>,
    config: ForwardingConfig,
    udp_sessions: Arc<AsyncRwLock<HashMap<u16, Weak<UdpSession>>>>,
    udp_relay_mode: Arc<ArcSwap<Option<UdpRelayMode>>>,
    remote_uni_stream_cnt: Counter,
    remote_bi_stream_cnt: Counter,
    max_concurrent_uni_streams: Arc<AtomicU32>,
    max_concurrent_bi_streams: Arc<AtomicU32>,
}

impl ForwardingConnection {
    /// Create a new forwarding connection to the exit server
    pub async fn new(ctx: Arc<AppContext>, config: ForwardingConfig) -> Result<Self, Error> {
        info!("Establishing forwarding connection to {}:{}", config.target_server, config.target_port);

        // 1. Load certificates
        let certs = Self::load_certs(&config.certificates, config.disable_native_certs)?;

        // 2. Create TLS configuration
        let mut crypto = if config.skip_cert_verify {
            #[derive(Debug)]
            struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

            impl SkipServerVerification {
                fn new() -> Arc<Self> {
                    Arc::new(Self(
                        rustls::crypto::CryptoProvider::get_default()
                            .expect("Crypto not found")
                            .clone(),
                    ))
                }
            }

            impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
                fn verify_server_cert(
                    &self,
                    _end_entity: &CertificateDer<'_>,
                    _intermediates: &[CertificateDer<'_>],
                    _server_name: &ServerName<'_>,
                    _ocsp: &[u8],
                    _now: UnixTime,
                ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error>
                {
                    Ok(rustls::client::danger::ServerCertVerified::assertion())
                }

                fn verify_tls12_signature(
                    &self,
                    message: &[u8],
                    cert: &CertificateDer<'_>,
                    dss: &rustls::DigitallySignedStruct,
                ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
                {
                    rustls::crypto::verify_tls12_signature(
                        message,
                        cert,
                        dss,
                        &self.0.signature_verification_algorithms,
                    )
                }

                fn verify_tls13_signature(
                    &self,
                    message: &[u8],
                    cert: &CertificateDer<'_>,
                    dss: &rustls::DigitallySignedStruct,
                ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
                {
                    rustls::crypto::verify_tls13_signature(
                        message,
                        cert,
                        dss,
                        &self.0.signature_verification_algorithms,
                    )
                }

                fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                    self.0.signature_verification_algorithms.supported_schemes()
                }
            }
            RustlsClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(SkipServerVerification::new())
                .with_no_client_auth()
        } else {
            RustlsClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(certs)
                .with_no_client_auth()
        };

        // 3. Configure ALPN and early data
        crypto.alpn_protocols = config.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
        crypto.enable_early_data = true;
        crypto.enable_sni = !config.disable_sni;

        // 4. Create QUIC client configuration
        let mut quic_config = ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(crypto).context("no initial cipher suite found")?,
        ));

        let mut tp_cfg = TransportConfig::default();
        tp_cfg
            .max_concurrent_bidi_streams(VarInt::from(32u32))
            .max_concurrent_uni_streams(VarInt::from(32u32))
            .max_idle_timeout(None);

        // 5. Configure congestion control
        match config.congestion_control {
            CongestionController::Cubic => {
                tp_cfg.congestion_controller_factory(Arc::new(CubicConfig::default()))
            }
            CongestionController::NewReno => {
                tp_cfg.congestion_controller_factory(Arc::new(NewRenoConfig::default()))
            }
            CongestionController::Bbr => {
                tp_cfg.congestion_controller_factory(Arc::new(BbrConfig::default()))
            }
        };

        quic_config.transport_config(Arc::new(tp_cfg));

        // 6. Resolve server address
        let server_addrs: Vec<SocketAddr> = net::lookup_host((config.target_server.as_str(), config.target_port))
            .await
            .context("failed to resolve exit server address")?
            .collect();

        if server_addrs.is_empty() {
            return Err(Error::Other(eyre!("no addresses resolved for exit server")));
        }

        let server_addr = server_addrs[0];

        // 7. Create UDP socket
        let socket = if server_addr.is_ipv4() {
            UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?
        } else {
            UdpSocket::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)))?
        };

        // 8. Create QUIC endpoint
        let mut endpoint = QuinnEndpoint::new(
            EndpointConfig::default(),
            None,
            socket,
            Arc::new(TokioRuntime),
        )?;

        endpoint.set_default_client_config(quic_config);

        // 9. Establish connection
        let connecting = endpoint.connect(server_addr, &config.target_server)
            .map_err(|e| Error::Other(eyre!("failed to initiate connection: {}", e)))?;
        let conn = if config.zero_rtt_handshake {
            match connecting.into_0rtt() {
                Ok((conn, _)) => conn,
                Err(connecting) => connecting.await
                    .map_err(|e| Error::Other(eyre!("failed to establish connection: {}", e)))?,
            }
        } else {
            connecting.await
                .map_err(|e| Error::Other(eyre!("failed to establish connection: {}", e)))?
        };

        // 10. Create model and authenticate
        let model = Model::<side::Client>::new(conn.clone());

        // Authenticate with exit server
        if let Some(uuid) = config.uuid {
            let password = Arc::from(config.password.as_bytes());
            match time::timeout(
                Duration::from_secs(5),
                model.authenticate(uuid, password),
            ).await {
                Ok(Ok(())) => {
                    info!("Successfully authenticated with exit server: {}", uuid);
                }
                Ok(Err(err)) => {
                    warn!("Failed to authenticate with exit server: {}", err);
                    return Err(Error::Other(eyre!("authentication failed: {}", err)));
                }
                Err(_) => {
                    warn!("Authentication with exit server timed out");
                    return Err(Error::Other(eyre!("authentication timeout")));
                }
            }
        }

        info!("Forwarding connection established to {}:{}", config.target_server, config.target_port);

        Ok(Self {
            ctx,
            inner: conn,
            model,
            config,
            udp_sessions: Arc::new(AsyncRwLock::new(HashMap::new())),
            udp_relay_mode: Arc::new(ArcSwap::new(None.into())),
            remote_uni_stream_cnt: Counter::new(),
            remote_bi_stream_cnt: Counter::new(),
            max_concurrent_uni_streams: Arc::new(AtomicU32::new(32)),
            max_concurrent_bi_streams: Arc::new(AtomicU32::new(32)),
        })
    }

    /// Load certificates for TLS configuration
    fn load_certs(paths: &[std::path::PathBuf], disable_native: bool) -> Result<RootCertStore, Error> {
        let mut certs = RootCertStore::empty();

        for cert_path in paths {
            let cert_chain = fs::read(cert_path).context("failed to read certificate chain")?;
            let cert_chain = if cert_path.extension().is_some_and(|x| x == "der") {
                vec![CertificateDer::from(cert_chain)]
            } else {
                rustls_pemfile::certs(&mut &*cert_chain)
                    .collect::<Result<_, _>>()
                    .context("invalid PEM-encoded certificate")?
            };
            certs.add_parsable_certificates(cert_chain);
        }

        if !disable_native {
            for cert in rustls_native_certs::load_native_certs().certs {
                _ = certs.add(cert);
            }
        }

        Ok(certs)
    }

    /// Forward a TCP connection to the exit server
    pub async fn forward_connect(&self, mut client_conn: tuic_quinn::Connect) -> Result<(), Error> {
        let target_addr = client_conn.addr().to_string();
        info!("[forwarding] [TCP] forwarding connection to {}", target_addr);

        // 1. Create a connection to the exit server
        match self.model.connect(client_conn.addr().clone()).await {
            Ok(mut exit_conn) => {
                info!("[forwarding] [TCP] established connection to exit server for {}", target_addr);

                // 2. Relay data between client and exit server using the same pattern as exchange_tcp
                let mut client_to_exit_buf = [0u8; 8192];
                let mut exit_to_client_buf = [0u8; 8192];

                let mut client_to_exit_bytes = 0;
                let mut exit_to_client_bytes = 0;
                let mut last_err = None;

                loop {
                    tokio::select! {
                        // Client -> Exit server
                        client_res = client_conn.recv.read(&mut client_to_exit_buf) => match client_res {
                            Ok(Some(num)) => {
                                client_to_exit_bytes += num;
                                if let Err(err) = exit_conn.send.write_all(&client_to_exit_buf[..num]).await {
                                    warn!("[forwarding] [TCP] client->exit write error for {}: {}", target_addr, err);
                                    last_err = Some(err.into());
                                    break;
                                }
                            },
                            Ok(None) => {
                                debug!("[forwarding] [TCP] client->exit stream closed for {}", target_addr);
                                break;
                            },
                            Err(err) => {
                                warn!("[forwarding] [TCP] client->exit read error for {}: {}", target_addr, err);
                                last_err = Some(err.into());
                                break;
                            }
                        },

                        // Exit server -> Client
                        exit_res = exit_conn.recv.read(&mut exit_to_client_buf) => match exit_res {
                            Ok(Some(num)) => {
                                exit_to_client_bytes += num;
                                if let Err(err) = client_conn.send.write_all(&exit_to_client_buf[..num]).await {
                                    warn!("[forwarding] [TCP] exit->client write error for {}: {}", target_addr, err);
                                    last_err = Some(err.into());
                                    break;
                                }
                            },
                            Ok(None) => {
                                debug!("[forwarding] [TCP] exit->client stream closed for {}", target_addr);
                                break;
                            },
                            Err(err) => {
                                warn!("[forwarding] [TCP] exit->client read error for {}: {}", target_addr, err);
                                last_err = Some(err.into());
                                break;
                            }
                        }
                    }
                }

                // Clean up connections
                if last_err.is_some() {
                    let _ = client_conn.reset(ERROR_CODE);
                    let _ = exit_conn.reset(ERROR_CODE);
                } else {
                    let _ = client_conn.finish();
                    let _ = exit_conn.finish();
                }

                info!("[forwarding] [TCP] connection relay completed for {} ({} bytes client->exit, {} bytes exit->client)", 
                      target_addr, client_to_exit_bytes, exit_to_client_bytes);

                if let Some(err) = last_err {
                    Err(Error::Other(err))
                } else {
                    Ok(())
                }
            }
            Err(e) => {
                warn!("[forwarding] [TCP] failed to connect to exit server for {}: {}", target_addr, e);
                let _ = client_conn.reset(ERROR_CODE);
                Err(Error::Model(e))
            }
        }
    }

    /// Forward a UDP packet to the exit server
    pub async fn forward_packet(&self, pkt: tuic_quinn::Packet, mode: UdpRelayMode) -> Result<(), Error> {
        let assoc_id = pkt.assoc_id();
        let pkt_id = pkt.pkt_id();
        let frag_id = pkt.frag_id();
        let frag_total = pkt.frag_total();

        info!("[forwarding] [UDP] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] fragment {}/{} forwarding to exit server", 
              frag_id + 1, frag_total);

        // Accept the packet to get the actual data and address
        let (packet_data, target_addr, assoc_id) = match pkt.accept().await {
            Ok(None) => {
                debug!("[forwarding] [UDP] [{assoc_id:#06x}] packet fragment not ready yet");
                return Ok(());
            }
            Ok(Some(res)) => res,
            Err(err) => {
                warn!("[forwarding] [UDP] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] fragment {}/{}: {}", 
                      frag_id + 1, frag_total, err);
                return Err(Error::Model(err));
            }
        };

        info!("[forwarding] [UDP] [{assoc_id:#06x}] forwarding packet to exit server for {}", target_addr);

        // Forward the packet to the exit server using the configured UDP relay mode
        match self.config.udp_relay_mode {
            UdpRelayMode::Native => {
                match self.model.packet_native(packet_data, target_addr, assoc_id) {
                    Ok(()) => {
                        debug!("[forwarding] [UDP] [{assoc_id:#06x}] [to-native] packet forwarded successfully");
                        Ok(())
                    }
                    Err(err) => {
                        warn!("[forwarding] [UDP] [{assoc_id:#06x}] [to-native] failed to forward packet: {}", err);
                        Err(Error::Other(err))
                    }
                }
            }
            UdpRelayMode::Quic => {
                match self.model.packet_quic(packet_data, target_addr, assoc_id).await {
                    Ok(()) => {
                        debug!("[forwarding] [UDP] [{assoc_id:#06x}] [to-quic] packet forwarded successfully");
                        Ok(())
                    }
                    Err(err) => {
                        warn!("[forwarding] [UDP] [{assoc_id:#06x}] [to-quic] failed to forward packet: {}", err);
                        Err(Error::Other(err))
                    }
                }
            }
        }
    }

    /// Check if the forwarding connection is still alive
    pub fn is_closed(&self) -> bool {
        self.inner.close_reason().is_some()
    }

    /// Close the forwarding connection
    pub fn close(&self) {
        self.inner.close(VarInt::from_u32(0), &[]);
    }

    /// Get connection ID for logging
    pub fn id(&self) -> u32 {
        self.inner.stable_id() as u32
    }
}

/// Manages forwarding connections pool
pub struct ForwardingManager {
    ctx: Arc<AppContext>,
    config: ForwardingConfig,
    connection: Arc<AsyncRwLock<Option<ForwardingConnection>>>,
}

impl ForwardingManager {
    pub fn new(ctx: Arc<AppContext>, config: ForwardingConfig) -> Self {
        Self {
            ctx,
            config,
            connection: Arc::new(AsyncRwLock::new(None)),
        }
    }

    /// Get or create a forwarding connection
    pub async fn get_connection(&self) -> Result<ForwardingConnection, Error> {
        let mut conn_guard = self.connection.write().await;

        match conn_guard.as_ref() {
            Some(conn) if !conn.is_closed() => Ok(conn.clone()),
            _ => {
                info!("Creating new forwarding connection to {}:{}", 
                      self.config.target_server, self.config.target_port);

                let new_conn = ForwardingConnection::new(self.ctx.clone(), self.config.clone()).await?;
                *conn_guard = Some(new_conn.clone());
                Ok(new_conn)
            }
        }
    }

    /// Check if forwarding is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

// Placeholder for UDP session - this would need to be implemented
struct UdpSession;
