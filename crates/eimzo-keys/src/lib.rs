//! Where key files live, what they contain, and the short-lived sessions that
//! RPC functions hand back to web pages. No network, no fixed paths: every
//! directory comes from `DiscoveryConfig`.

pub mod discovery;
pub mod session;

pub use discovery::{Discovery, DiscoveryConfig, KeyInfo, KeyKind};
pub use session::{SessionData, SessionType, Sessions};
