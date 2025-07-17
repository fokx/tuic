use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    str::FromStr,
    time::Duration,
};

use educe::Educe;
use notify::{RecommendedWatcher, Watcher};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

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

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Educe)]
#[educe(Default)]
pub enum CongestionController {
    #[educe(Default)]
    Bbr,
    Cubic,
    NewReno,
}

// TODO remove in 2.0.0
impl FromStr for CongestionController {
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

pub trait FutResultExt<T, E, Fut> {
    async fn log_err(self) -> Option<T>;
}
impl<T, Fut> FutResultExt<T, eyre::Report, Fut> for Fut
where
    Fut: std::future::Future<Output = Result<T, eyre::Report>>,
{
    #[inline(always)]
    async fn log_err(self) -> Option<T> {
        match self.await {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::error!("{:?}", e);
                None
            }
        }
    }
}

pub async fn async_watcher(
    interval: Duration,
) -> eyre::Result<(RecommendedWatcher, broadcast::Receiver<()>)> {
    let (tx, rx) = broadcast::channel(1);
    let config = notify::Config::default();
    config.with_poll_interval(interval);
    let watcher = RecommendedWatcher::new(
        move |res: Result<notify::Event, notify::Error>| {
            if res.is_ok() {
                tx.send(()).unwrap();
            }
        },
        config,
    )?;

    Ok((watcher, rx))
}
