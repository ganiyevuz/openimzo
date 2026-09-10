//! The wire contract of E-IMZO: the functions a web page can call, the status
//! codes and localized reasons it gets back. No sockets here; phase 2B puts
//! this dispatcher on the original's ports.

pub mod dispatch;
pub mod error;
pub mod i18n;
pub mod model;
pub mod origin;
pub mod plugins;
pub mod ui;

pub use i18n::Lang;
pub use model::{Request, Response};
