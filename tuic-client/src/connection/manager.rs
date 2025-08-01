use std::{
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};

use anyhow::anyhow;
// use tokio::io::AsyncReadExt;
use tokio::time;
use tracing::{debug, error, info, warn};

use super::{Connection, CONNECTION_MANAGER};
use crate::{
    config::{LoadBalancingStrategy, MultiPathConfig, Relay},
    connection::load_balancer::{
        ConnectionStatus, LoadBalancer, MovingAverage, PathConnection, SelectionStrategy,
    },
    error::Error,
};

/// Manages multiple connections for multi-path routing
pub struct ConnectionManager {
    paths: Arc<Vec<PathConnection>>,
    load_balancer: LoadBalancer,
    config: MultiPathConfig,
}

/// Connection performance metrics
#[derive(Debug, Clone)]
pub struct ConnectionMetrics {
    pub latency: MovingAverage,
    pub packet_loss: f64,
    pub last_success: Instant,
    pub failure_count: u32,
    pub success_count: u32,
    pub total_requests: u64,
}

/// Statistics for a single path
#[derive(Debug, Clone)]
pub struct PathStatistics {
    pub index: usize,
    pub server: String,
    pub status: ConnectionStatus,
    pub avg_latency: Duration,
    pub packet_loss: f64,
    pub success_rate: f64,
    pub total_requests: u64,
    pub active_connections: u32,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub upload_bandwidth: Duration,
    pub download_bandwidth: Duration,
    pub priority_weight: f64,
    pub adaptive_weight: f64,
}

impl ConnectionManager {
    pub fn get_relays(&self) -> Vec<Relay> {
        self.paths.iter().map(|path| path.config.clone()).collect()
    }

    pub async fn new(relays: Vec<Relay>, config: MultiPathConfig) -> Result<Self, Error> {
        let mut paths = Vec::new();
        let mut failed_relays = Vec::new();

        for relay in relays {
            match PathConnection::new(relay.clone(), &config).await {
                Ok(path) => {
                    info!(
                        "[multi-path] Successfully initialized relay: {}:{}",
                        relay.server.0, relay.server.1
                    );
                    paths.push(path);
                }
                Err(err) => {
                    warn!(
                        "[multi-path] Failed to initialize relay {}:{}: {}",
                        relay.server.0, relay.server.1, err
                    );
                    failed_relays.push((relay, err));
                }
            }
        }

        if paths.is_empty() {
            return Err(Error::Other(anyhow!(
                "All configured relays failed to initialize. Failed relays: {:?}",
                failed_relays
                    .iter()
                    .map(|(relay, err)| format!("{}:{} ({})", relay.server.0, relay.server.1, err))
                    .collect::<Vec<_>>()
            )));
        }

        if !failed_relays.is_empty() {
            warn!(
                "[multi-path] {} out of {} relays failed to initialize, continuing with {} \
                 working relays",
                failed_relays.len(),
                failed_relays.len() + paths.len(),
                paths.len()
            );
        }

        let selection_strategy = match config.load_balancing_strategy {
            LoadBalancingStrategy::Random => SelectionStrategy::Random,
            LoadBalancingStrategy::WeightedRoundRobin => SelectionStrategy::WeightedRoundRobin,
            LoadBalancingStrategy::LatencyBased => SelectionStrategy::LatencyBased,
            LoadBalancingStrategy::LeastConnections => SelectionStrategy::LeastConnections,
            LoadBalancingStrategy::ConsistentHashing => SelectionStrategy::ConsistentHashing,
            LoadBalancingStrategy::Adaptive => SelectionStrategy::Adaptive,
        };
        let load_balancer = LoadBalancer::new(selection_strategy);

        // Store config flags before moving config
        let enable_bandwidth_aggregation = config.enable_bandwidth_aggregation;
        let enable_adaptive_weights = config.enable_adaptive_weights;

        let manager = Self {
            paths: Arc::new(paths),
            load_balancer,
            config,
        };

        // Initialize minimum connections and log initial statistics
        let _ = manager.ensure_minimum_connections().await;

        // Start health check task
        manager.start_health_check_and_log_task().await;
        // manager.start_maintenance_task().await;
        // manager.log_stats().await;

        // Start bandwidth monitoring task if enabled
        // if enable_bandwidth_aggregation {
        //     manager.start_bandwidth_monitoring_task().await;
        // }

        // Start metrics update task if adaptive weights are enabled
        // if enable_adaptive_weights {
        //     manager.start_metrics_update_task().await;
        // }

        Ok(manager)
    }

    /// Get the best available connection based on current metrics
    pub async fn get_connection(&self) -> Result<Connection, Error> {
        let selected_path = self
            .load_balancer
            .select_path(&self.paths, &self.config)
            .await?;

        // Get connection from the pool
        let mut pool = selected_path.connection_pool.write().await;
        let connection = pool.get_connection(&selected_path.endpoint).await?;

        // Update metrics
        let mut metrics = selected_path.metrics.write().await;
        metrics.total_requests += 1;
        metrics.last_success = Instant::now();

        // Increment active connections counter
        selected_path
            .active_connections
            .fetch_add(1, Ordering::Relaxed);

        info!(
            "[multi-path] Retrieved connection from pool for path: {}:{}",
            selected_path.config.server.0, selected_path.config.server.1
        );

        Ok(connection)
    }

    /// Create a new connection for a specific path
    async fn create_connection_for_path(&self, path: &PathConnection) -> Result<Connection, Error> {
        debug!(
            "[multi-path] Creating connection for path: {}:{}",
            path.config.server.0, path.config.server.1
        );

        // Increment active connections counter
        path.active_connections.fetch_add(1, Ordering::Relaxed);

        // Update connection attempt metrics
        let mut metrics = path.metrics.write().await;
        metrics.connection_attempts += 1;
        drop(metrics);

        match path.endpoint.connect().await {
            Ok(connection) => {
                // Update successful connection metrics
                let mut metrics = path.metrics.write().await;
                metrics.successful_connections += 1;
                drop(metrics);

                info!(
                    "[multi-path] Successfully created connection for path: {}:{}",
                    path.config.server.0, path.config.server.1
                );
                Ok(connection)
            }
            Err(err) => {
                // Decrement counter on failure
                path.active_connections.fetch_sub(1, Ordering::Relaxed);

                // Update path status and metrics
                let mut metrics = path.metrics.write().await;
                metrics.failure_count += 1;

                // Reset success count when failures start occurring
                if metrics.failure_count == 1 {
                    metrics.success_count = 0;
                }

                let mut status = path.status.write().await;
                let current_status = status.clone();

                // Determine new status based on failure count and current state
                *status = match current_status {
                    ConnectionStatus::Healthy => {
                        if metrics.failure_count >= self.config.failure_threshold {
                            ConnectionStatus::Failed
                        } else {
                            ConnectionStatus::Degraded
                        }
                    }
                    ConnectionStatus::Degraded | ConnectionStatus::Recovering => {
                        if metrics.failure_count >= self.config.failure_threshold {
                            ConnectionStatus::Failed
                        } else {
                            ConnectionStatus::Degraded
                        }
                    }
                    ConnectionStatus::Failed => {
                        // Already failed, stay failed
                        ConnectionStatus::Failed
                    }
                };

                error!(
                    "[multi-path] Failed to create connection for path: {}:{}, error: {}",
                    path.config.server.0, path.config.server.1, err
                );
                Err(err)
            }
        }
    }

    /// Start the health check background task
    async fn start_health_check_and_log_task(&self) {
        let paths = self.paths.clone();
        let config = self.config.clone();
        let interval = self.config.health_check_interval;
        warn!("start health check every {}s", interval.as_secs());
        tokio::spawn(async move {
            let mut interval_timer = time::interval(interval);

            loop {
                interval_timer.tick().await;

                for path in paths.iter() {
                    if let Err(e) = Self::health_check_path_simple(path, &config).await {
                        warn!("[multi-path] Health check failed for path: {}", e);
                    }
                }

                if let Some(manager_lock) = CONNECTION_MANAGER.get() {
                    let temp_manager = manager_lock.read().await;
                    let stats = temp_manager.get_path_statistics().await;
                    for stat in stats {
                        warn!(
                            "[check] Path {}:  {:?}. Pool has {} connection",
                            stat.server,
                            stat.status,
                            stat.active_connections
                        );
                    }
                }
            }
        });
    }

    /// Perform health check on a single path
    async fn health_check_path(
        path: &PathConnection,
        config: &MultiPathConfig,
    ) -> Result<(), Error> {
        let start = Instant::now();

        // Try to get a connection from the pool for health check
        let mut pool = path.connection_pool.write().await;

        // Clean up idle connections first
        pool.cleanup_idle_connections();

        // Try to get a connection for health check
        match pool.get_connection(&path.endpoint).await {
            Ok(conn) => {
                if conn.is_closed() {
                    let mut metrics = path.metrics.write().await;
                    metrics.failure_count += 1;

                    // Reset success count when failures start occurring
                    if metrics.failure_count == 1 {
                        metrics.success_count = 0;
                    }

                    let mut status = path.status.write().await;
                    let current_status = status.clone();

                    // Determine new status based on failure count and current state
                    *status = match current_status {
                        ConnectionStatus::Healthy => {
                            if metrics.failure_count >= config.failure_threshold {
                                ConnectionStatus::Failed
                            } else {
                                ConnectionStatus::Degraded
                            }
                        }
                        ConnectionStatus::Degraded | ConnectionStatus::Recovering => {
                            if metrics.failure_count >= config.failure_threshold {
                                ConnectionStatus::Failed
                            } else {
                                ConnectionStatus::Degraded
                            }
                        }
                        ConnectionStatus::Failed => {
                            // Already failed, stay failed
                            ConnectionStatus::Failed
                        }
                    };

                    return Err(Error::Other(anyhow!("Connection is closed")));
                }

                // Update latency metrics
                let latency = start.elapsed();
                let mut metrics = path.metrics.write().await;
                metrics.latency.add(latency);
                metrics.last_success = Instant::now();
                metrics.success_count += 1;

                // Update status based on metrics using configuration thresholds
                let mut status = path.status.write().await;
                let current_status = status.clone();

                // Determine new status based on failure/success counts and current state
                *status = match current_status {
                    ConnectionStatus::Failed => {
                        // Path is currently failed, check if it should recover
                        if metrics.success_count >= config.recovery_threshold {
                            // Reset failure count on successful recovery
                            metrics.failure_count = 0;
                            ConnectionStatus::Healthy
                        } else {
                            ConnectionStatus::Failed
                        }
                    }
                    ConnectionStatus::Degraded | ConnectionStatus::Recovering => {
                        // Path is degraded or recovering, check thresholds
                        if metrics.failure_count >= config.failure_threshold {
                            ConnectionStatus::Failed
                        } else if metrics.success_count >= config.recovery_threshold {
                            // Reset failure count on successful recovery
                            metrics.failure_count = 0;
                            ConnectionStatus::Healthy
                        } else {
                            ConnectionStatus::Recovering
                        }
                    }
                    ConnectionStatus::Healthy => {
                        // Path is healthy, check if it should degrade
                        if metrics.failure_count >= config.failure_threshold {
                            ConnectionStatus::Failed
                        } else if metrics.failure_count > 0 {
                            ConnectionStatus::Degraded
                        } else {
                            ConnectionStatus::Healthy
                        }
                    }
                };

                // Return connection to pool
                pool.return_connection(conn);
            }
            Err(_) => {
                let mut metrics = path.metrics.write().await;
                metrics.failure_count += 1;

                // Reset success count when failures start occurring
                if metrics.failure_count == 1 {
                    metrics.success_count = 0;
                }

                let mut status = path.status.write().await;
                let current_status = status.clone();

                // Determine new status based on failure count and current state
                *status = match current_status {
                    ConnectionStatus::Healthy => {
                        if metrics.failure_count >= config.failure_threshold {
                            ConnectionStatus::Failed
                        } else {
                            ConnectionStatus::Degraded
                        }
                    }
                    ConnectionStatus::Degraded | ConnectionStatus::Recovering => {
                        if metrics.failure_count >= config.failure_threshold {
                            ConnectionStatus::Failed
                        } else {
                            ConnectionStatus::Degraded
                        }
                    }
                    ConnectionStatus::Failed => {
                        // Already failed, stay failed
                        ConnectionStatus::Failed
                    }
                };

                return Err(Error::Other(anyhow!(
                    "Failed to get connection for health check"
                )));
            }
        }

        let mut last_check = path.last_health_check.write().await;
        *last_check = Instant::now();

        Ok(())
    }
    /// Perform health check on a single path
    async fn health_check_path_simple(
        path: &PathConnection,
        config: &MultiPathConfig,
    ) -> Result<(), Error> {
        let start = Instant::now();

        // Try to get a connection from the pool for health check
        let mut pool = path.connection_pool.write().await;

        // Clean up idle connections first
        pool.cleanup_idle_connections();

        // Try to get a connection for health check
        match pool.get_connection(&path.endpoint).await {
            Ok(conn) => {
                if conn.is_closed() {
                    let mut status = path.status.write().await;

                    *status = ConnectionStatus::Failed;
                    // pool.clear_pool();

                    return Err(Error::Other(anyhow!("Connection is closed")));
                }

                let mut status = path.status.write().await;

                // Determine new status based on failure/success counts and current state
                *status = ConnectionStatus::Healthy;

                // Return connection to pool
                pool.return_connection(conn);
            }
            Err(_) => {
                let mut status = path.status.write().await;

                // Determine new status based on failure count and current state
                *status = ConnectionStatus::Failed;
                pool.clear_pool();

                return Err(Error::Other(anyhow!(
                    "Failed to get connection for health check"
                )));
            }
        }

        let mut last_check = path.last_health_check.write().await;
        *last_check = Instant::now();

        Ok(())
    }

    /// Start the bandwidth monitoring background task
    async fn start_bandwidth_monitoring_task(&self) {
        let paths = self.paths.clone();
        let interval = self.config.bandwidth_measurement_interval;

        tokio::spawn(async move {
            let mut interval_timer = time::interval(interval);

            loop {
                interval_timer.tick().await;

                for path in paths.iter() {
                    // Update bandwidth metrics for each path
                    let mut bandwidth_tracker = path.bandwidth_tracker.write().await;
                    let metrics = path.metrics.read().await;

                    // Get current byte counts from metrics
                    let bytes_sent = metrics.bytes_sent.load(Ordering::Relaxed);
                    let bytes_received = metrics.bytes_received.load(Ordering::Relaxed);

                    // Update bandwidth tracker
                    bandwidth_tracker.update_bandwidth(bytes_sent, bytes_received);
                }
            }
        });
    }

    /// Start the metrics update background task for adaptive weights
    async fn start_metrics_update_task(&self) {
        let paths = self.paths.clone();
        let config = self.config.clone();
        let interval = self.config.metrics_update_interval;

        tokio::spawn(async move {
            let mut interval_timer = time::interval(interval);

            loop {
                interval_timer.tick().await;

                for path in paths.iter() {
                    // Update adaptive weights and priority weights
                    Self::update_path_weights(path, &config).await;
                }

                // Ensure minimum connections are maintained
                if let Some(_manager_ref) =
                    std::sync::Weak::upgrade(&std::sync::Arc::downgrade(&std::sync::Arc::new(())))
                {
                    // This is a workaround to get a reference to self in the
                    // spawned task
                    // In a real implementation, we'd pass the manager reference
                    // properly
                }
            }
        });
    }

    /// Start a maintenance task that ensures minimum connections and logs statistics
    async fn start_maintenance_task(&self) {
        tokio::spawn(async move {
            let mut interval_timer = time::interval(Duration::from_secs(10)); // Run every minute

            loop {
                interval_timer.tick().await;

                if let Some(manager_lock) = CONNECTION_MANAGER.get() {
                    let temp_manager = manager_lock.read().await;
                    temp_manager.get_path_statistics().await;
                    // Ensure minimum connections
                    let _ = temp_manager.ensure_minimum_connections().await;
                }
            }
        });
    }

    /// Update adaptive weights and priority weights for a path
    async fn update_path_weights(path: &PathConnection, config: &MultiPathConfig) {
        let mut metrics = path.metrics.write().await;
        let mut priority_weight = path.priority_weight.write().await;
        let bandwidth_tracker = path.bandwidth_tracker.read().await;

        // Calculate adaptive weight based on multiple factors
        let latency_ms = metrics.latency.average().as_millis() as f64;
        let latency_factor = if latency_ms > 0.0 {
            1000.0 / latency_ms
        } else {
            1000.0
        };
        let loss_factor = 1.0 - metrics.packet_loss;
        let success_rate = if metrics.total_requests > 0 {
            metrics.success_count as f64 / metrics.total_requests as f64
        } else {
            1.0
        };

        // Include bandwidth in adaptive weight calculation
        let upload_bw = bandwidth_tracker.upload_bandwidth.average().as_secs_f64();
        let download_bw = bandwidth_tracker.download_bandwidth.average().as_secs_f64();
        let bandwidth_factor = (upload_bw + download_bw) / 2.0;

        // Combine factors with configuration weights
        let adaptive_weight = (latency_factor * config.latency_weight)
            + (loss_factor * config.loss_weight)
            + (success_rate * 0.2)
            + (bandwidth_factor * 0.1);

        metrics.adaptive_weight = adaptive_weight;

        // Update priority weight based on path priority and adaptive weight
        if config.enable_path_prioritization {
            let priority_factor = 1000.0 / (path.config.priority as f64 + 1.0);
            *priority_weight = adaptive_weight * priority_factor;
        } else {
            *priority_weight = adaptive_weight;
        }
    }

    /// Get statistics for all paths
    pub async fn get_path_statistics(&self) -> Vec<PathStatistics> {
        let mut stats = Vec::new();

        for (index, path) in self.paths.iter().enumerate() {
            let metrics = path.metrics.read().await;
            let status = path.status.read().await;
            let bandwidth_tracker = path.bandwidth_tracker.read().await;
            let priority_weight = path.priority_weight.read().await;

            // Create a ConnectionMetrics instance for compatibility and use its fields
            let connection_metrics = ConnectionMetrics::new();
            let _latency = connection_metrics.latency.average();
            let _packet_loss = connection_metrics.packet_loss;
            let _last_success = connection_metrics.last_success;
            let _failure_count = connection_metrics.failure_count;
            let _success_count = connection_metrics.success_count;
            let _total_requests = connection_metrics.total_requests;

            stats.push(PathStatistics {
                index,
                server: format!("{}:{}", path.config.server.0, path.config.server.1),
                status: status.clone(),
                avg_latency: metrics.latency.average(),
                packet_loss: metrics.packet_loss,
                success_rate: if metrics.total_requests > 0 {
                    metrics.success_count as f64 / metrics.total_requests as f64
                } else {
                    0.0
                },
                total_requests: metrics.total_requests,
                active_connections: path.active_connections.load(Ordering::Relaxed),
                bytes_sent: metrics.bytes_sent.load(Ordering::Relaxed),
                bytes_received: metrics.bytes_received.load(Ordering::Relaxed),
                upload_bandwidth: bandwidth_tracker.upload_bandwidth.average(),
                download_bandwidth: bandwidth_tracker.download_bandwidth.average(),
                priority_weight: *priority_weight,
                adaptive_weight: metrics.adaptive_weight,
            });
        }

        stats
    }

    /// Create backup connections for paths that are below minimum pool size
    pub async fn ensure_minimum_connections(&self) -> Result<(), Error> {
        for path in self.paths.iter() {
            let pool = path.connection_pool.read().await;
            let current_size = pool.connections.len();
            let min_size = pool.min_size;

            if current_size < min_size as usize {
                drop(pool); // Release read lock

                // Create additional connections using create_connection_for_path
                let needed = min_size as usize - current_size;
                for _ in 0..needed {
                    if let Ok(conn) = self.create_connection_for_path(path).await {
                        let mut pool = path.connection_pool.write().await;
                        pool.return_connection(conn);
                    }
                }
            }
        }
        Ok(())
    }

    async fn log_stats(&self) {
        let interval = self.config.health_check_interval;

        tokio::spawn(async move {
            let mut interval_timer = time::interval(interval);

            loop {
                interval_timer.tick().await;

                if let Some(manager_lock) = CONNECTION_MANAGER.get() {
                    let manager = manager_lock.read().await;
                    let stats = manager.get_path_statistics().await;
                    info!("[multi-path] Initialized {} paths", stats.len());

                    // Log detailed statistics for each path to use PathStatistics fields
                    for stat in &stats {
                        debug!(
                            "[multi-path] Path {}: server={}, status={:?}, latency={}ms, \
                             loss={:.2}%, success_rate={:.2}%, requests={}, connections={}, \
                             sent={}B, received={}B, upload_bw={}ms, download_bw={}ms, \
                             priority={:.2}, adaptive={:.2}",
                            stat.index,
                            stat.server,
                            stat.status,
                            stat.avg_latency.as_millis(),
                            stat.packet_loss * 100.0,
                            stat.success_rate * 100.0,
                            stat.total_requests,
                            stat.active_connections,
                            stat.bytes_sent,
                            stat.bytes_received,
                            stat.upload_bandwidth.as_millis(),
                            stat.download_bandwidth.as_millis(),
                            stat.priority_weight,
                            stat.adaptive_weight
                        );
                    }
                }
            }
        });
    }
}

impl ConnectionMetrics {
    fn new() -> Self {
        Self {
            latency: MovingAverage::new(10), // Keep last 10 measurements
            packet_loss: 0.0,
            last_success: Instant::now(),
            failure_count: 0,
            success_count: 0,
            total_requests: 0,
        }
    }
}
