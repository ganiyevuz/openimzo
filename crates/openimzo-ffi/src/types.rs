//! The values that cross into Swift. None of these ever carries a private
//! key or a password: the shell asks the person for a password and hands it
//! back through `UiDelegate`, and it never sees one otherwise.

#[derive(Clone, Debug, uniffi::Record)]
pub struct EngineConfig {
    /// Run on ports that do not collide with a running original.
    pub dev_mode: bool,
    /// Where TLS material, settings and the site list are stored.
    pub app_support_dir: String,
    /// Where logs are written.
    pub logs_dir: String,
    /// Directories to search for key files, beyond the volumes root.
    pub extra_folders: Vec<String>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct EngineStatus {
    /// The plain listener is up.
    pub ws: bool,
    /// The TLS listener is up.
    pub wss: bool,
    /// This machine's trust store accepts our certificate.
    pub tls_trusted: bool,
    pub dev_mode: bool,
    /// The port the plain listener binds to: the original's own port
    /// normally, or the development one when `dev_mode` is set. Named
    /// explicitly rather than left for the shell to hardcode, since it is
    /// the one thing that actually changes between the two.
    pub ws_port: u16,
    /// The port the TLS listener binds to, same reasoning as `ws_port`.
    pub wss_port: u16,
}

/// A key the person can see in the app's list: the wire fields a site sees,
/// plus the certificate summary the app shows.
#[derive(Clone, Debug, uniffi::Record)]
pub struct KeyEntry {
    pub disk: String,
    pub path: String,
    pub name: String,
    pub alias: String,
    pub full_path: String,
    pub subject_name: String,
    pub issuer_name: String,
    pub serial_number: String,
    pub valid_from: String,
    pub valid_to: String,
    pub public_key_alg_name: String,
    /// True when `valid_to` is in the past.
    pub expired: bool,
}

/// The certificate-summary half of `KeyEntry`, read from a password-protected PFX by
/// `Engine::unlock_key` once the person has supplied its password — everything a `KeyEntry`
/// already carries for a YKS, minus the fields (`disk`, `path`, `name`, `alias`, `full_path`)
/// the shell already has from the row it is unlocking, and never the password itself, which lives
/// only long enough to open the file.
#[derive(Clone, Debug, uniffi::Record)]
pub struct CertificateSummary {
    pub subject_name: String,
    pub issuer_name: String,
    pub serial_number: String,
    pub valid_from: String,
    pub valid_to: String,
    pub public_key_alg_name: String,
    /// True when `valid_to` is in the past.
    pub expired: bool,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct Site {
    /// The full origin, scheme and port included, which is how permission
    /// answers are keyed.
    pub origin: String,
    /// A verified API key is cached for this domain.
    pub registered: bool,
    /// The person chose "always allow" for this origin.
    pub allowed_always: bool,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct Settings {
    /// What websites are answered in: `openimzo_rpc::i18n::Lang`'s own two
    /// codes, `"ru"` or `"uz"`, and nothing else — this one is a wire
    /// contract.
    pub lang: String,
    /// What the person using the app reads: `openimzo_rpc::i18n::UiLang`'s
    /// three codes, `"ru"`, `"uz"` or `"en"`. Separate from `lang` because
    /// the app's chrome has an English the original never had, and giving
    /// `lang` a third value would change what every integrated site sees.
    /// The core reads it for the two pages it serves on `127.0.0.1`.
    pub ui_lang: String,
    pub launch_at_login: bool,
    pub developer_mode: bool,
    /// Remember a password for six hours when the person ticks the box.
    pub remember_passwords: bool,
    /// Ask before seeding the random generator, once per site.
    pub ask_before_randseed: bool,
    pub keep_activity_log: bool,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ActivityEntry {
    pub at: String,
    pub origin: String,
    pub function: String,
    pub outcome: String,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum EngineError {
    #[error("the engine is not running")]
    NotRunning,
    #[error("that key file could not be opened")]
    KeyFile,
    #[error("the password was not accepted")]
    Password,
    #[error("the operation failed")]
    Failed,
}
