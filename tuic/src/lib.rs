#![doc = include_str!("../README.md")]

pub use self::protocol::{
    Address, Authenticate, Connect, Dissociate, Header, Heartbeat, Packet, VERSION,
};
#[cfg(any(feature = "async_marshal", feature = "marshal"))]
pub use self::unmarshal::UnmarshalError;

mod protocol;

#[cfg(any(feature = "async_marshal", feature = "marshal"))]
mod marshal;

#[cfg(any(feature = "async_marshal", feature = "marshal"))]
mod unmarshal;

#[cfg(feature = "model")]
pub mod model;
