use std::{
    env::ArgsOs,
    fmt::Display,
    fs::File,
    io::{BufReader, Error as IoError},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use humantime::Duration as HumanDuration;
use lexopt::{Arg, Error as ArgumentError, Parser};
use serde::{Deserialize, Deserializer, de::Error as DeError};
use serde_json::Error as SerdeError;
use thiserror::Error;
use uuid::Uuid;

use crate::utils::{CongestionControl, UdpRelayMode};

#[derive(Clone, Copy, Debug)]
pub enum LoadBalancingStrategy {
    Random,
    WeightedRoundRobin,
    LatencyBased,
    LeastConnections,
    ConsistentHashing,
    Adaptive,
}

impl FromStr for LoadBalancingStrategy {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "weighted_round_robin" | "weighted-round-robin" => Ok(Self::WeightedRoundRobin),
            "random" => Ok(Self::Random),
            "latency_based" | "latency-based" => Ok(Self::LatencyBased),
            "least_connections" | "least-connections" => Ok(Self::LeastConnections),
            "consistent_hashing" | "consistent-hashing" => Ok(Self::ConsistentHashing),
            "adaptive" => Ok(Self::Adaptive),
            _ => Err("invalid load balancing strategy"),
        }
    }
}

const HELP_MSG: &str = r#"
Usage tuic-client [arguments]

Arguments:
    -c, --config <path>     Path to the config file (required)
    -v, --version           Print the version
    -h, --help              Print this help message
"#;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(flatten)]
    pub relay_config: RelayConfig,

    pub local: Local,

    #[serde(default)]
    pub multi_path: MultiPathConfig,

    #[serde(default = "default::log_level")]
    pub log_level: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RelayConfig {
    #[serde(rename = "relay")]
    Single(Relay),
    #[serde(rename = "relays")]
    Multiple(Vec<Relay>),
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct MultiPathConfig {
    #[serde(
        default = "default::multi_path::health_check_interval",
        deserialize_with = "deserialize_duration"
    )]
    pub health_check_interval: Duration,

    #[serde(default = "default::multi_path::failure_threshold")]
    pub failure_threshold: u32,

    #[serde(default = "default::multi_path::recovery_threshold")]
    pub recovery_threshold: u32,

    #[serde(default = "default::multi_path::latency_weight")]
    pub latency_weight: f64,

    #[serde(default = "default::multi_path::loss_weight")]
    pub loss_weight: f64,

    // Connection pooling settings
    #[serde(default = "default::multi_path::max_connections_per_path")]
    pub max_connections_per_path: u32,

    #[serde(default = "default::multi_path::min_connections_per_path")]
    pub min_connections_per_path: u32,

    #[serde(
        default = "default::multi_path::connection_idle_timeout",
        deserialize_with = "deserialize_duration"
    )]
    pub connection_idle_timeout: Duration,

    // Load balancing strategy
    #[serde(
        default = "default::multi_path::load_balancing_strategy",
        deserialize_with = "deserialize_from_str"
    )]
    pub load_balancing_strategy: LoadBalancingStrategy,

    // Bandwidth aggregation settings
    #[serde(default = "default::multi_path::enable_bandwidth_aggregation")]
    pub enable_bandwidth_aggregation: bool,

    #[serde(
        default = "default::multi_path::bandwidth_measurement_interval",
        deserialize_with = "deserialize_duration"
    )]
    pub bandwidth_measurement_interval: Duration,

    // Real-time metrics settings
    #[serde(default = "default::multi_path::enable_adaptive_weights")]
    pub enable_adaptive_weights: bool,

    #[serde(
        default = "default::multi_path::metrics_update_interval",
        deserialize_with = "deserialize_duration"
    )]
    pub metrics_update_interval: Duration,

    // Path selection settings
    #[serde(default = "default::multi_path::enable_path_prioritization")]
    pub enable_path_prioritization: bool,

    #[serde(default = "default::multi_path::consistent_hashing_replicas")]
    pub consistent_hashing_replicas: u32,
}

impl Default for MultiPathConfig {
    fn default() -> Self {
        Self {
            health_check_interval: default::multi_path::health_check_interval(),
            failure_threshold: default::multi_path::failure_threshold(),
            recovery_threshold: default::multi_path::recovery_threshold(),
            latency_weight: default::multi_path::latency_weight(),
            loss_weight: default::multi_path::loss_weight(),
            max_connections_per_path: default::multi_path::max_connections_per_path(),
            min_connections_per_path: default::multi_path::min_connections_per_path(),
            connection_idle_timeout: default::multi_path::connection_idle_timeout(),
            load_balancing_strategy: default::multi_path::load_balancing_strategy(),
            enable_bandwidth_aggregation: default::multi_path::enable_bandwidth_aggregation(),
            bandwidth_measurement_interval: default::multi_path::bandwidth_measurement_interval(),
            enable_adaptive_weights: default::multi_path::enable_adaptive_weights(),
            metrics_update_interval: default::multi_path::metrics_update_interval(),
            enable_path_prioritization: default::multi_path::enable_path_prioritization(),
            consistent_hashing_replicas: default::multi_path::consistent_hashing_replicas(),
        }
    }
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Relay {
    #[serde(deserialize_with = "deserialize_server")]
    pub server: (String, u16),

    pub uuid: Uuid,

    #[serde(deserialize_with = "deserialize_password")]
    pub password: Arc<[u8]>,

    pub ip: Option<IpAddr>,

    #[serde(default = "default::relay::certificates")]
    pub certificates: Vec<PathBuf>,

    #[serde(
        default = "default::relay::udp_relay_mode",
        deserialize_with = "deserialize_from_str"
    )]
    pub udp_relay_mode: UdpRelayMode,

    #[serde(
        default = "default::relay::congestion_control",
        deserialize_with = "deserialize_from_str"
    )]
    pub congestion_control: CongestionControl,

    #[serde(
        default = "default::relay::alpn",
        deserialize_with = "deserialize_alpn"
    )]
    pub alpn: Vec<Vec<u8>>,

    #[serde(default = "default::relay::zero_rtt_handshake")]
    pub zero_rtt_handshake: bool,

    #[serde(default = "default::relay::disable_sni")]
    pub disable_sni: bool,

    #[serde(
        default = "default::relay::timeout",
        deserialize_with = "deserialize_duration"
    )]
    pub timeout: Duration,

    #[serde(
        default = "default::relay::heartbeat",
        deserialize_with = "deserialize_duration"
    )]
    pub heartbeat: Duration,

    #[serde(default = "default::relay::disable_native_certs")]
    pub disable_native_certs: bool,

    #[serde(default = "default::relay::send_window")]
    pub send_window: u64,

    #[serde(default = "default::relay::receive_window")]
    pub receive_window: u32,

    #[serde(default = "default::relay::initial_mtu")]
    pub initial_mtu: u16,

    #[serde(default = "default::relay::min_mtu")]
    pub min_mtu: u16,

    #[serde(default = "default::relay::gso")]
    pub gso: bool,

    #[serde(default = "default::relay::pmtu")]
    pub pmtu: bool,

    #[serde(
        default = "default::relay::gc_interval",
        deserialize_with = "deserialize_duration"
    )]
    pub gc_interval: Duration,

    #[serde(
        default = "default::relay::gc_lifetime",
        deserialize_with = "deserialize_duration"
    )]
    pub gc_lifetime: Duration,

    #[serde(default = "default::relay::skip_cert_verify")]
    pub skip_cert_verify: bool,

    // Multi-path specific settings
    #[serde(default = "default::relay::priority")]
    pub priority: u32,

    #[serde(default = "default::relay::enabled")]
    pub enabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Local {
    pub server: SocketAddr,

    #[serde(deserialize_with = "deserialize_optional_bytes", default)]
    pub username: Option<Vec<u8>>,

    #[serde(deserialize_with = "deserialize_optional_bytes", default)]
    pub password: Option<Vec<u8>>,

    pub dual_stack: Option<bool>,

    #[serde(default = "default::local::max_packet_size")]
    pub max_packet_size: usize,
}

impl Config {
    pub fn parse(args: ArgsOs) -> Result<Self, ConfigError> {
        let mut parser = Parser::from_iter(args);
        let mut path = None;

        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Short('c') | Arg::Long("config") => {
                    if path.is_none() {
                        path = Some(parser.value()?);
                    } else {
                        return Err(ConfigError::Argument(arg.unexpected()));
                    }
                }
                Arg::Short('v') | Arg::Long("version") => {
                    return Err(ConfigError::Version(env!("CARGO_PKG_VERSION")));
                }
                Arg::Short('h') | Arg::Long("help") => return Err(ConfigError::Help(HELP_MSG)),
                _ => return Err(ConfigError::Argument(arg.unexpected())),
            }
        }

        if path.is_none() {
            return Err(ConfigError::NoConfig);
        }

        let file = File::open(path.unwrap())?;
        let reader = BufReader::new(file);
        Ok(serde_json::from_reader(reader)?)
    }
}

mod default {

    pub mod relay {
        use std::{path::PathBuf, time::Duration};

        use crate::utils::{CongestionControl, UdpRelayMode};

        pub fn certificates() -> Vec<PathBuf> {
            Vec::new()
        }

        pub fn udp_relay_mode() -> UdpRelayMode {
            UdpRelayMode::Native
        }

        pub fn congestion_control() -> CongestionControl {
            CongestionControl::Cubic
        }

        pub fn alpn() -> Vec<Vec<u8>> {
            Vec::new()
        }

        pub fn zero_rtt_handshake() -> bool {
            false
        }

        pub fn disable_sni() -> bool {
            false
        }

        pub fn timeout() -> Duration {
            Duration::from_secs(8)
        }

        pub fn heartbeat() -> Duration {
            Duration::from_secs(3)
        }

        pub fn disable_native_certs() -> bool {
            false
        }

        pub fn send_window() -> u64 {
            8 * 1024 * 1024 * 2
        }

        pub fn receive_window() -> u32 {
            8 * 1024 * 1024
        }

        // struct.TransportConfig#method.initial_mtu
        pub fn initial_mtu() -> u16 {
            1200
        }

        // struct.TransportConfig#method.min_mtu
        pub fn min_mtu() -> u16 {
            1200
        }

        // struct.TransportConfig#method.enable_segmentation_offload
        // aka. Generic Segmentation Offload
        pub fn gso() -> bool {
            true
        }

        // struct.TransportConfig#method.mtu_discovery_config
        // if not pmtu() -> mtu_discovery_config(None)
        pub fn pmtu() -> bool {
            true
        }

        pub fn gc_interval() -> Duration {
            Duration::from_secs(3)
        }

        pub fn gc_lifetime() -> Duration {
            Duration::from_secs(15)
        }

        pub fn skip_cert_verify() -> bool {
            false
        }

        // Multi-path specific defaults
        pub fn priority() -> u32 {
            100 // Default priority, lower numbers = higher priority
        }

        pub fn enabled() -> bool {
            true
        }
    }

    pub mod local {
        pub fn max_packet_size() -> usize {
            1500
        }
    }

    pub mod multi_path {
        use std::time::Duration;

        use crate::config::LoadBalancingStrategy;

        pub fn health_check_interval() -> Duration {
            Duration::from_secs(5)
        }

        pub fn failure_threshold() -> u32 {
            3
        }

        pub fn recovery_threshold() -> u32 {
            2
        }

        pub fn latency_weight() -> f64 {
            0.7
        }

        pub fn loss_weight() -> f64 {
            0.3
        }

        // Connection pooling defaults
        pub fn max_connections_per_path() -> u32 {
            10
        }

        pub fn min_connections_per_path() -> u32 {
            1
        }

        pub fn connection_idle_timeout() -> Duration {
            Duration::from_secs(300) // 5 minutes
        }

        // Load balancing defaults
        pub fn load_balancing_strategy() -> LoadBalancingStrategy {
            LoadBalancingStrategy::WeightedRoundRobin
        }

        // Bandwidth aggregation defaults
        pub fn enable_bandwidth_aggregation() -> bool {
            false
        }

        pub fn bandwidth_measurement_interval() -> Duration {
            Duration::from_secs(10)
        }

        // Real-time metrics defaults
        pub fn enable_adaptive_weights() -> bool {
            true
        }

        pub fn metrics_update_interval() -> Duration {
            Duration::from_secs(30)
        }

        // Path prioritization defaults
        pub fn enable_path_prioritization() -> bool {
            false
        }

        // Consistent hashing defaults
        pub fn consistent_hashing_replicas() -> u32 {
            100
        }
    }

    pub fn log_level() -> String {
        "info".into()
    }
}

pub fn deserialize_from_str<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: FromStr,
    <T as FromStr>::Err: Display,
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    T::from_str(&s).map_err(DeError::custom)
}

pub fn deserialize_server<'de, D>(deserializer: D) -> Result<(String, u16), D::Error>
where
    D: Deserializer<'de>,
{
    let mut s = String::deserialize(deserializer)?;

    let (domain, port) = s
        .rsplit_once(':')
        .ok_or(DeError::custom("invalid server address"))?;

    let port = port.parse().map_err(DeError::custom)?;
    s.truncate(domain.len());

    Ok((s, port))
}

pub fn deserialize_password<'de, D>(deserializer: D) -> Result<Arc<[u8]>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(Arc::from(s.into_bytes().into_boxed_slice()))
}

pub fn deserialize_alpn<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = Vec::<String>::deserialize(deserializer)?;
    Ok(s.into_iter().map(|alpn| alpn.into_bytes()).collect())
}

pub fn deserialize_optional_bytes<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(Some(s.into_bytes()))
}

pub fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;

    s.parse::<HumanDuration>()
        .map(|d| *d)
        .map_err(DeError::custom)
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error(transparent)]
    Argument(#[from] ArgumentError),
    #[error("no config file specified")]
    NoConfig,
    #[error("{0}")]
    Version(&'static str),
    #[error("{0}")]
    Help(&'static str),
    #[error(transparent)]
    Io(#[from] IoError),
    #[error(transparent)]
    Serde(#[from] SerdeError),
}
