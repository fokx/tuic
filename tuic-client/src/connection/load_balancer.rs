use std::{
    collections::{HashMap, VecDeque},
    hash::{DefaultHasher, Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::anyhow;
use quinn::{
    ClientConfig, Endpoint as QuinnEndpoint, EndpointConfig, TokioRuntime, TransportConfig, VarInt,
    congestion::{BbrConfig, CubicConfig, NewRenoConfig},
    crypto::rustls::QuicClientConfig,
};
use rustls::{
    ClientConfig as RustlsClientConfig,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use tokio::sync::RwLock as AsyncRwLock;
use uuid::Uuid;

use crate::{
    config::{MultiPathConfig, Relay},
    connection::Connection,
    error::Error,
    utils,
    utils::{CongestionControl, ServerAddr, UdpRelayMode},
};
/// Connection pool for managing multiple connections per path
pub struct ConnectionPool {
    pub(crate) connections: VecDeque<PooledConnection>,
    max_size: u32,
    pub(crate) min_size: u32,
    idle_timeout: Duration,
}

/// A connection in the pool with metadata
pub struct PooledConnection {
    connection: Connection,
    created_at: Instant,
    last_used: Instant,
    usage_count: u64,
}

/// Bandwidth tracking for a path
#[derive(Debug, Clone)]
pub struct BandwidthTracker {
    pub upload_bandwidth: MovingAverage,
    pub download_bandwidth: MovingAverage,
    pub last_measurement: Instant,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub measurement_window: Duration,
}
impl BandwidthTracker {
    fn new() -> Self {
        Self {
            upload_bandwidth: MovingAverage::new(10),
            download_bandwidth: MovingAverage::new(10),
            last_measurement: Instant::now(),
            total_bytes_sent: 0,
            total_bytes_received: 0,
            measurement_window: Duration::from_secs(10),
        }
    }

    pub(crate) fn update_bandwidth(&mut self, bytes_sent: u64, bytes_received: u64) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_measurement);

        if elapsed >= self.measurement_window {
            let upload_rate = bytes_sent as f64 / elapsed.as_secs_f64();
            let download_rate = bytes_received as f64 / elapsed.as_secs_f64();

            self.upload_bandwidth
                .add(Duration::from_secs_f64(upload_rate));
            self.download_bandwidth
                .add(Duration::from_secs_f64(download_rate));

            self.total_bytes_sent += bytes_sent;
            self.total_bytes_received += bytes_received;
            self.last_measurement = now;
        }
    }
}

/// Connection status
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionStatus {
    Healthy,
    Degraded,
    Failed,
    Recovering,
}

/// Enhanced connection metrics with bandwidth tracking
#[derive(Debug)]
pub struct EnhancedConnectionMetrics {
    pub latency: MovingAverage,
    pub packet_loss: f64,
    pub last_success: Instant,
    pub failure_count: u32,
    pub success_count: u32,
    pub total_requests: u64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub connection_attempts: u64,
    pub successful_connections: u64,
    pub adaptive_weight: f64,
}

#[derive(Debug, Clone)]
pub enum SelectionStrategy {
    Random,
    WeightedRoundRobin,
    LatencyBased,
    LeastConnections,
    ConsistentHashing,
    Adaptive,
}

/// Simple moving average for latency tracking
#[derive(Debug, Clone)]
pub struct MovingAverage {
    values: VecDeque<Duration>,
    max_size: usize,
    sum: Duration,
}

/// Load balancer for selecting the best connection
pub struct LoadBalancer {
    selection_strategy: SelectionStrategy,
}

/// Consistent hashing ring for load balancing
#[derive(Debug)]
pub struct ConsistentHashRing {
    ring: HashMap<u64, usize>, // hash -> path_index
    sorted_hashes: Vec<u64>,   // Keep sorted list for binary search
    replicas: u32,
}

impl ConsistentHashRing {
    fn new(replicas: u32) -> Self {
        Self {
            ring: HashMap::new(),
            sorted_hashes: Vec::new(),
            replicas,
        }
    }

    fn add_path(&mut self, path_index: usize, path_id: &str) {
        for i in 0..self.replicas {
            let mut hasher = DefaultHasher::new();
            format!("{path_id}:{i}").hash(&mut hasher);
            let hash = hasher.finish();
            self.ring.insert(hash, path_index);
        }

        // Rebuild sorted list after adding
        self.rebuild_sorted_hashes();
    }

    #[allow(dead_code)]
    fn remove_path(&mut self, path_id: &str) {
        // Remove all replicas for this path
        for i in 0..self.replicas {
            let mut hasher = DefaultHasher::new();
            format!("{path_id}:{i}").hash(&mut hasher);
            let hash = hasher.finish();
            self.ring.remove(&hash);
        }

        // Rebuild sorted list after removal
        self.rebuild_sorted_hashes();
    }

    fn get_path(&self, key: &str) -> Option<usize> {
        if self.sorted_hashes.is_empty() {
            return None;
        }

        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let hash = hasher.finish();

        // Binary search for the first hash >= our hash
        match self.sorted_hashes.binary_search(&hash) {
            Ok(index) => {
                // Exact match found
                self.ring.get(&self.sorted_hashes[index]).copied()
            }
            Err(index) => {
                if index < self.sorted_hashes.len() {
                    // Found insertion point, use the hash at that position
                    self.ring.get(&self.sorted_hashes[index]).copied()
                } else {
                    // Wrap around to the first hash
                    self.ring.get(&self.sorted_hashes[0]).copied()
                }
            }
        }
    }

    fn rebuild_sorted_hashes(&mut self) {
        self.sorted_hashes = self.ring.keys().copied().collect();
        self.sorted_hashes.sort_unstable();
    }

    // Optional: Get distribution statistics
    #[allow(dead_code)]
    fn get_stats(&self) -> (usize, usize) {
        (self.ring.len(), self.sorted_hashes.len())
    }
}

/// Endpoint for a specific path
pub(crate) struct PathEndpoint {
    ep: QuinnEndpoint,
    server: ServerAddr,
    uuid: Uuid,
    password: Arc<[u8]>,
    udp_relay_mode: UdpRelayMode,
    zero_rtt_handshake: bool,
    heartbeat: Duration,
    gc_interval: Duration,
    gc_lifetime: Duration,
}

impl PathEndpoint {
    async fn new(cfg: &Relay) -> Result<Self, Error> {
        let certs = utils::load_certs(cfg.certificates.clone(), cfg.disable_native_certs)?;

        let mut crypto = if cfg.skip_cert_verify {
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

        crypto.alpn_protocols = cfg.alpn.clone();
        crypto.enable_early_data = true;
        crypto.enable_sni = !cfg.disable_sni;

        let mut config = ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(crypto)
                .map_err(|e| Error::Other(anyhow!("no initial cipher suite found: {}", e)))?,
        ));
        let mut tp_cfg = TransportConfig::default();

        tp_cfg
            .max_concurrent_bidi_streams(VarInt::from(32u32))
            .max_concurrent_uni_streams(VarInt::from(32u32))
            .send_window(cfg.send_window)
            .stream_receive_window(VarInt::from_u32(cfg.receive_window))
            .max_idle_timeout(None)
            .initial_mtu(cfg.initial_mtu)
            .min_mtu(cfg.min_mtu);

        if !cfg.gso {
            tp_cfg.enable_segmentation_offload(false);
        }
        if !cfg.pmtu {
            tp_cfg.mtu_discovery_config(None);
        }

        match cfg.congestion_control {
            CongestionControl::Cubic => {
                tp_cfg.congestion_controller_factory(Arc::new(CubicConfig::default()))
            }
            CongestionControl::NewReno => {
                tp_cfg.congestion_controller_factory(Arc::new(NewRenoConfig::default()))
            }
            CongestionControl::Bbr => {
                tp_cfg.congestion_controller_factory(Arc::new(BbrConfig::default()))
            }
        };

        config.transport_config(Arc::new(tp_cfg));

        let server = ServerAddr::new(cfg.server.0.clone(), cfg.server.1, cfg.ip);
        let server_ip: Option<IpAddr> =
            match tokio::time::timeout(Duration::from_secs(10), server.resolve()).await {
                Ok(Ok(mut addrs)) => match addrs.next() {
                    Some(SocketAddr::V4(v4)) => Some(v4.ip().to_owned().into()),
                    Some(SocketAddr::V6(v6)) => Some(v6.ip().to_owned().into()),
                    None => None,
                },
                Ok(Err(err)) => return Err(err),
                Err(_) => {
                    return Err(Error::Other(anyhow!(
                        "DNS resolution timeout for server: {}:{}",
                        cfg.server.0,
                        cfg.server.1
                    )));
                }
            };
        let server_ip = server_ip.ok_or_else(|| {
            Error::Other(anyhow!(
                "Server ip not found for: {}:{}",
                cfg.server.0,
                cfg.server.1
            ))
        })?;
        let socket = if server_ip.is_ipv4() {
            UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?
        } else {
            UdpSocket::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)))?
        };

        let mut ep = QuinnEndpoint::new(
            EndpointConfig::default(),
            None,
            socket,
            Arc::new(TokioRuntime),
        )?;

        ep.set_default_client_config(config);

        Ok(Self {
            ep,
            server,
            uuid: cfg.uuid,
            password: cfg.password.clone(),
            udp_relay_mode: cfg.udp_relay_mode,
            zero_rtt_handshake: cfg.zero_rtt_handshake,
            heartbeat: cfg.heartbeat,
            gc_interval: cfg.gc_interval,
            gc_lifetime: cfg.gc_lifetime,
        })
    }

    pub(crate) async fn connect(&self) -> Result<Connection, Error> {
        let mut last_err = None;

        // Add timeout for DNS resolution
        let addrs = match tokio::time::timeout(Duration::from_secs(10), self.server.resolve()).await
        {
            Ok(Ok(addrs)) => addrs,
            Ok(Err(err)) => return Err(err),
            Err(_) => {
                return Err(Error::Other(anyhow!(
                    "DNS resolution timeout during connection to: {}",
                    self.server.server_name()
                )));
            }
        };

        for addr in addrs {
            let connect_to = async {
                let conn = self.ep.connect(addr, self.server.server_name())?;
                let (conn, zero_rtt_accepted) = if self.zero_rtt_handshake {
                    match conn.into_0rtt() {
                        Ok((conn, zero_rtt_accepted)) => (conn, Some(zero_rtt_accepted)),
                        Err(conn) => (conn.await?, None),
                    }
                } else {
                    (conn.await?, None)
                };

                Ok((conn, zero_rtt_accepted))
            };

            // Add timeout for connection attempt
            match tokio::time::timeout(Duration::from_secs(10), connect_to).await {
                Ok(Ok((conn, zero_rtt_accepted))) => {
                    return Ok(Connection::new(
                        conn,
                        zero_rtt_accepted,
                        self.udp_relay_mode,
                        self.uuid,
                        self.password.clone(),
                        self.heartbeat,
                        self.gc_interval,
                        self.gc_lifetime,
                    ));
                }
                Ok(Err(err)) => last_err = Some(err),
                Err(_) => last_err = Some(Error::Other(anyhow!("Connection timeout to: {}", addr))),
            }
        }

        Err(last_err.unwrap_or(Error::DnsResolve))
    }
}

/// Represents a single path/connection with its metrics
pub struct PathConnection {
    pub(crate) connection_pool: AsyncRwLock<ConnectionPool>,
    pub(crate) metrics: AsyncRwLock<EnhancedConnectionMetrics>,
    pub(crate) config: Relay,
    pub(crate) status: AsyncRwLock<ConnectionStatus>,
    pub(crate) last_health_check: AsyncRwLock<Instant>,
    pub(crate) endpoint: PathEndpoint,
    pub(crate) active_connections: AtomicU32,
    pub(crate) bandwidth_tracker: AsyncRwLock<BandwidthTracker>,
    pub(crate) priority_weight: AsyncRwLock<f64>,
}
impl PathConnection {
    pub(crate) async fn new(
        config: Relay,
        multi_path_config: &MultiPathConfig,
    ) -> Result<Self, Error> {
        let endpoint = PathEndpoint::new(&config).await?;

        Ok(Self {
            connection_pool: AsyncRwLock::new(ConnectionPool::new(
                multi_path_config.max_connections_per_path,
                multi_path_config.min_connections_per_path,
                multi_path_config.connection_idle_timeout,
            )),
            metrics: AsyncRwLock::new(EnhancedConnectionMetrics::new()),
            config,
            status: AsyncRwLock::new(ConnectionStatus::Healthy),
            last_health_check: AsyncRwLock::new(Instant::now()),
            endpoint,
            active_connections: AtomicU32::new(0),
            bandwidth_tracker: AsyncRwLock::new(BandwidthTracker::new()),
            priority_weight: AsyncRwLock::new(1.0),
        })
    }
}
impl ConnectionPool {
    fn new(max_size: u32, min_size: u32, idle_timeout: Duration) -> Self {
        Self {
            connections: VecDeque::new(),
            max_size,
            min_size,
            idle_timeout,
        }
    }

    pub(crate) async fn get_connection(
        &mut self,
        endpoint: &PathEndpoint,
    ) -> Result<Connection, Error> {
        // Try to get an existing connection from the pool
        while let Some(mut pooled_conn) = self.connections.pop_front() {
            if !pooled_conn.connection.is_closed() {
                pooled_conn.last_used = Instant::now();
                pooled_conn.usage_count += 1;
                return Ok(pooled_conn.connection);
            }
        }

        // No available connections, create a new one
        endpoint.connect().await
    }

    pub(crate) fn return_connection(&mut self, connection: Connection) {
        if self.connections.len() < self.max_size as usize {
            let pooled_conn = PooledConnection {
                connection,
                created_at: Instant::now(),
                last_used: Instant::now(),
                usage_count: 1,
            };
            self.connections.push_back(pooled_conn);
        } else {
            // If pool is full, just drop the connection
            drop(connection);
        }
    }

    pub(crate) fn clear_pool(&mut self) {
        self.connections.clear();
    }
    pub(crate) fn cleanup_idle_connections(&mut self) {
        let now = Instant::now();
        // First, remove closed connections
        self.connections.retain(|conn| !conn.connection.is_closed());

        // Then, remove idle connections but maintain minimum pool size
        let mut connections_to_keep = Vec::new();
        let mut connections_to_remove = Vec::new();

        for conn in self.connections.drain(..) {
            let is_idle = now.duration_since(conn.last_used) >= self.idle_timeout;
            let is_old = now.duration_since(conn.created_at) > Duration::from_secs(3600); // 1 hour max age

            if is_idle || is_old {
                connections_to_remove.push(conn);
            } else {
                connections_to_keep.push(conn);
            }
        }

        // Keep connections up to max_size, prioritizing newer and more recently used
        // ones
        connections_to_keep.sort_by(|a, b| {
            // Sort by last_used (more recent first), then by created_at (newer first)
            b.last_used
                .cmp(&a.last_used)
                .then(b.created_at.cmp(&a.created_at))
        });

        // Ensure we maintain at least min_size connections
        let mut final_connections = connections_to_keep;
        let current_count = final_connections.len();

        if current_count < self.min_size as usize {
            // Add back some connections from the removal list if needed
            connections_to_remove.sort_by(|a, b| {
                b.last_used
                    .cmp(&a.last_used)
                    .then(b.created_at.cmp(&a.created_at))
            });

            let needed = (self.min_size as usize).saturating_sub(current_count);
            final_connections.extend(connections_to_remove.into_iter().take(needed));
        }

        // Restore connections to the pool
        self.connections = final_connections.into();
    }
}

impl EnhancedConnectionMetrics {
    fn new() -> Self {
        Self {
            latency: MovingAverage::new(10), // Keep last 10 measurements
            packet_loss: 0.0,
            last_success: Instant::now(),
            failure_count: 0,
            success_count: 0,
            total_requests: 0,
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            connection_attempts: 0,
            successful_connections: 0,
            adaptive_weight: 1.0,
        }
    }
}

impl LoadBalancer {
    pub(crate) fn new(strategy: SelectionStrategy) -> Self {
        Self {
            selection_strategy: strategy,
        }
    }

    pub(crate) async fn select_path<'a>(
        &self,
        paths: &'a [PathConnection],
        config: &MultiPathConfig,
    ) -> Result<&'a PathConnection, Error> {
        match self.selection_strategy {
            SelectionStrategy::Random => self.random_selection(paths).await,
            SelectionStrategy::WeightedRoundRobin => {
                self.weighted_round_robin_selection(paths, config).await
            }
            SelectionStrategy::LatencyBased => self.latency_based_selection(paths).await,
            SelectionStrategy::LeastConnections => self.least_connections_selection(paths).await,
            SelectionStrategy::ConsistentHashing => {
                self.consistent_hashing_selection(paths, config).await
            }
            SelectionStrategy::Adaptive => self.adaptive_selection(paths, config).await,
        }
    }

    async fn random_selection<'a>(
        &self,
        paths: &'a [PathConnection],
    ) -> Result<&'a PathConnection, Error> {
        // Filter healthy and enabled paths
        let mut healthy_paths = Vec::new();

        for path in paths {
            let status = path.status.read().await;
            if *status == ConnectionStatus::Healthy && path.config.enabled {
                healthy_paths.push(path);
            }
        }

        if healthy_paths.is_empty() {
            return Err(Error::Other(anyhow!("No healthy paths available")));
        }

        // Use thread-local RNG for better performance
        use rand::Rng;
        let idx = rand::rng().random_range(0..healthy_paths.len());
        Ok(healthy_paths[idx])
    }

    async fn weighted_round_robin_selection<'a>(
        &self,
        paths: &'a [PathConnection],
        config: &MultiPathConfig,
    ) -> Result<&'a PathConnection, Error> {
        let mut best_path = None;
        let mut best_score = f64::NEG_INFINITY;

        for path in paths {
            let status = path.status.read().await;
            if *status != ConnectionStatus::Healthy || !path.config.enabled {
                continue;
            }

            let metrics = path.metrics.read().await;

            // Calculate weighted score based on latency and packet loss
            let latency_ms = metrics.latency.average().as_millis() as f64;
            let latency_score = if latency_ms > 0.0 {
                1000.0 / latency_ms
            } else {
                1000.0
            };
            let loss_score = 1.0 - metrics.packet_loss;

            let total_score =
                (latency_score * config.latency_weight) + (loss_score * config.loss_weight);

            if total_score > best_score {
                best_score = total_score;
                best_path = Some(path);
            }
        }

        best_path.ok_or_else(|| Error::Other(anyhow!("No healthy paths available")))
    }

    async fn latency_based_selection<'a>(
        &self,
        paths: &'a [PathConnection],
    ) -> Result<&'a PathConnection, Error> {
        let mut best_path = None;
        let mut best_latency = Duration::MAX;

        for path in paths {
            let status = path.status.read().await;
            if *status != ConnectionStatus::Healthy || !path.config.enabled {
                continue;
            }

            let metrics = path.metrics.read().await;
            let avg_latency = metrics.latency.average();

            if avg_latency < best_latency {
                best_latency = avg_latency;
                best_path = Some(path);
            }
        }

        best_path.ok_or_else(|| Error::Other(anyhow!("No healthy paths available")))
    }

    async fn least_connections_selection<'a>(
        &self,
        paths: &'a [PathConnection],
    ) -> Result<&'a PathConnection, Error> {
        let mut best_path = None;
        let mut least_connections = u32::MAX;

        for path in paths {
            let status = path.status.read().await;
            if *status != ConnectionStatus::Healthy || !path.config.enabled {
                continue;
            }

            let active_connections = path.active_connections.load(Ordering::Relaxed);

            if active_connections < least_connections {
                least_connections = active_connections;
                best_path = Some(path);
            }
        }

        best_path.ok_or_else(|| Error::Other(anyhow!("No healthy paths available")))
    }

    async fn consistent_hashing_selection<'a>(
        &self,
        paths: &'a [PathConnection],
        config: &MultiPathConfig,
    ) -> Result<&'a PathConnection, Error> {
        // Build consistent hash ring with enabled and healthy paths
        let mut ring = ConsistentHashRing::new(config.consistent_hashing_replicas);
        let mut enabled_paths = Vec::new();

        for (index, path) in paths.iter().enumerate() {
            let status = path.status.read().await;
            if *status == ConnectionStatus::Healthy && path.config.enabled {
                enabled_paths.push((index, path));
            }
        }

        if enabled_paths.is_empty() {
            return Err(Error::Other(anyhow!("No enabled paths available")));
        }

        // Add paths to the ring
        for (index, path) in &enabled_paths {
            let path_id = format!("{}:{}", path.config.server.0, path.config.server.1);
            ring.add_path(*index, &path_id);
        }

        // Use thread ID as the key for consistent selection
        let key = format!("{:?}", std::thread::current().id());

        if let Some(selected_index) = ring.get_path(&key) {
            if let Some((_, path)) = enabled_paths.iter().find(|(idx, _)| *idx == selected_index) {
                return Ok(path);
            }
        }

        // Fallback to first enabled path if ring selection fails
        Ok(enabled_paths[0].1)
    }

    async fn adaptive_selection<'a>(
        &self,
        paths: &'a [PathConnection],
        config: &MultiPathConfig,
    ) -> Result<&'a PathConnection, Error> {
        let mut best_path = None;
        let mut best_score = f64::NEG_INFINITY;

        for path in paths {
            let status = path.status.read().await;
            if *status != ConnectionStatus::Healthy || !path.config.enabled {
                continue;
            }

            let metrics = path.metrics.read().await;

            // Adaptive scoring considers multiple factors
            let latency_ms = metrics.latency.average().as_millis() as f64;
            let latency_score = if latency_ms > 0.0 {
                1000.0 / latency_ms
            } else {
                1000.0
            };
            let loss_score = 1.0 - metrics.packet_loss;
            let success_rate = if metrics.total_requests > 0 {
                metrics.success_count as f64 / metrics.total_requests as f64
            } else {
                1.0
            };

            // Priority factor (lower priority number = higher weight)
            let priority_score = 1000.0 / (path.config.priority as f64 + 1.0);

            // Connection load factor
            let active_connections = path.active_connections.load(Ordering::Relaxed) as f64;
            let load_score = if active_connections > 0.0 {
                100.0 / active_connections
            } else {
                100.0
            };

            // Combine all factors with adaptive weights
            let total_score = (latency_score * config.latency_weight)
                + (loss_score * config.loss_weight)
                + (success_rate * 0.2)
                + (priority_score * 0.1)
                + (load_score * 0.1);

            if total_score > best_score {
                best_score = total_score;
                best_path = Some(path);
            }
        }

        best_path.ok_or_else(|| Error::Other(anyhow!("No healthy paths available")))
    }
}
impl MovingAverage {
    pub(crate) fn new(max_size: usize) -> Self {
        Self {
            values: VecDeque::with_capacity(max_size),
            max_size,
            sum: Duration::ZERO,
        }
    }

    pub(crate) fn add(&mut self, value: Duration) {
        if self.values.len() >= self.max_size {
            if let Some(old_value) = self.values.pop_front() {
                self.sum -= old_value;
            }
        }

        self.values.push_back(value);
        self.sum += value;
    }

    pub(crate) fn average(&self) -> Duration {
        if self.values.is_empty() {
            Duration::ZERO
        } else {
            self.sum / self.values.len() as u32
        }
    }
}
