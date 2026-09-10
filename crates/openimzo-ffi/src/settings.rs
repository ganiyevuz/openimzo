//! `Settings` persistence: `<app_support_dir>/settings.json`
//! (the design spec), read
//! once by `Engine::new` and rewritten by `Engine::update_settings`.
//!
//! `Settings` itself (`crate::types::Settings`) carries only a
//! `uniffi::Record` derive — it is shared with Swift and has no reason to
//! also know how to serialize itself to JSON — so this module keeps its own
//! serde-shaped mirror and converts between the two, rather than adding a
//! derive to a type this task's brief does not list as its own to change.

use crate::types::Settings;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const FILE_NAME: &str = "settings.json";

#[derive(Serialize, Deserialize)]
struct SettingsFile {
    lang: String,
    launch_at_login: bool,
    developer_mode: bool,
    remember_passwords: bool,
    ask_before_randseed: bool,
    keep_activity_log: bool,
}

impl From<&Settings> for SettingsFile {
    fn from(s: &Settings) -> Self {
        SettingsFile {
            lang: s.lang.clone(),
            launch_at_login: s.launch_at_login,
            developer_mode: s.developer_mode,
            remember_passwords: s.remember_passwords,
            ask_before_randseed: s.ask_before_randseed,
            keep_activity_log: s.keep_activity_log,
        }
    }
}

impl From<SettingsFile> for Settings {
    fn from(f: SettingsFile) -> Self {
        Settings {
            lang: f.lang,
            launch_at_login: f.launch_at_login,
            developer_mode: f.developer_mode,
            remember_passwords: f.remember_passwords,
            ask_before_randseed: f.ask_before_randseed,
            keep_activity_log: f.keep_activity_log,
        }
    }
}

/// What a person who has never touched Settings gets. `remember_passwords`
/// and `ask_before_randseed` default to the behavior this workspace already
/// had before either was configurable — remembering allowed, asking before
/// seeding — so a first run changes nothing about how those two feel;
/// `lang` matches `openimzo_rpc::Lang::default()` (`"ru"`).
fn default_settings() -> Settings {
    Settings {
        lang: "ru".to_string(),
        launch_at_login: false,
        developer_mode: false,
        remember_passwords: true,
        ask_before_randseed: true,
        keep_activity_log: false,
    }
}

fn path(app_support_dir: &str) -> PathBuf {
    Path::new(app_support_dir).join(FILE_NAME)
}

/// Reads `settings.json`, or falls back to `default_settings()` for a first
/// run (no file yet) or a file that turns out not to parse — corrupt
/// settings must never stop the engine from starting.
pub(crate) fn load(app_support_dir: &str) -> Settings {
    let file = path(app_support_dir);
    let bytes = match std::fs::read(&file) {
        Ok(bytes) => bytes,
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::debug!(error = %e, "settings.json could not be read; using defaults");
            }
            return default_settings();
        }
    };
    match serde_json::from_slice::<SettingsFile>(&bytes) {
        Ok(parsed) => parsed.into(),
        Err(e) => {
            tracing::debug!(error = %e, "settings.json could not be parsed; using defaults");
            default_settings()
        }
    }
}

/// Rewrites `settings.json` in full. Called from `Engine::update_settings`
/// on the blocking pool, same discipline as every other disk write in this
/// workspace. Unlike a key file, losing this one costs nothing but a
/// preference reset, so this writes directly rather than going through the
/// key file's atomic temp-then-rename helper.
pub(crate) fn save(app_support_dir: &str, settings: &Settings) {
    let file = path(app_support_dir);
    if let Some(dir) = file.parent() {
        if let Err(e) = std::fs::create_dir_all(dir) {
            tracing::debug!(error = %e, "could not create the app support directory for settings.json");
            return;
        }
    }
    let data = match serde_json::to_vec_pretty(&SettingsFile::from(settings)) {
        Ok(data) => data,
        Err(e) => {
            tracing::debug!(error = %e, "settings could not be serialized");
            return;
        }
    };
    if let Err(e) = std::fs::write(&file, data) {
        tracing::debug!(error = %e, "settings.json could not be written");
    }
}
