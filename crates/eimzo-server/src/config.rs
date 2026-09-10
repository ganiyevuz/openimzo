//! What the server needs to know before it binds.

use std::path::PathBuf;

/// The original's ports. Development mode moves both so the two programs can
/// run side by side while this one is being built; the spec calls for that
/// explicitly, because otherwise testing means quitting the original.
pub const WS_PORT: u16 = 64646;
pub const WSS_PORT: u16 = 64443;
pub const DEV_WS_PORT: u16 = 64746;
pub const DEV_WSS_PORT: u16 = 64543;

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub ws_port: u16,
    pub wss_port: u16,
    /// True when the ports are moved out of the original's way.
    pub dev_mode: bool,
    /// Where the per-install TLS key and certificate live.
    pub material_dir: PathBuf,
}

impl ServerConfig {
    /// The ports a real install uses.
    pub fn production(material_dir: PathBuf) -> Self {
        ServerConfig { ws_port: WS_PORT, wss_port: WSS_PORT, dev_mode: false, material_dir }
    }

    /// Ports that do not collide with a running original.
    pub fn development(material_dir: PathBuf) -> Self {
        ServerConfig { ws_port: DEV_WS_PORT, wss_port: DEV_WSS_PORT, dev_mode: true, material_dir }
    }
}
