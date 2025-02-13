use std::{env, process};
use env_logger::Builder as LoggerBuilder;

use crate::{
    config::{Config, ConfigError},
    connection::Connection,
    socks5::Server as Socks5Server,
};

mod config;
mod connection;
mod error;
mod socks5;
mod utils;

#[tokio::main]
async fn main() {
    let cfg = match Config::parse(env::args_os()) {
        Ok(cfg) => cfg,
        Err(ConfigError::Version(msg) | ConfigError::Help(msg)) => {
            println!("{msg}");
            process::exit(0);
        }
        Err(err) => {
            eprintln!("{err}");
            process::exit(1);
        }
    };

    LoggerBuilder::new()
            .filter_level(cfg.log_level)
            .format_module_path(false)
            .format_target(false)
            .init();
    rustls::crypto::ring::default_provider().install_default().expect("Failed to install rustls crypto provider");
    match Connection::set_config(cfg.relay) {
        Ok(()) => {}
        Err(err) => {
            eprintln!("{err}");
            process::exit(1);
        }
    }

    match Socks5Server::set_config(cfg.local) {
        Ok(()) => {}
        Err(err) => {
            eprintln!("{err}");
            process::exit(1);
        }
    }

    Socks5Server::start().await;
}
