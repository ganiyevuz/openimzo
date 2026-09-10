//! Finding key files. Every directory comes from `DiscoveryConfig`; this
//! module never consults the environment or a hard-coded path.

use openimzo_pki::{pkcs12, x509, ytks, PkiError};
use serde::Serialize;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    Pfx,
    Ytks,
}

impl KeyKind {
    pub fn extension(self) -> &'static str {
        match self {
            KeyKind::Pfx => "pfx",
            KeyKind::Ytks => "yks",
        }
    }
}

/// The `DSKEYS` convention: a directory of that name, directly under a volume
/// or a user-chosen folder, is where Uzbek key files are kept.
pub const DSKEYS: &str = "DSKEYS";

#[derive(Clone, Debug)]
pub struct DiscoveryConfig {
    /// Where removable volumes are mounted. `/Volumes` on macOS.
    pub volumes_dir: PathBuf,
    /// Folders the user added by hand in the app's settings.
    pub extra_folders: Vec<PathBuf>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        DiscoveryConfig { volumes_dir: PathBuf::from("/Volumes"), extra_folders: Vec::new() }
    }
}

/// One key a site can choose. Field names are the original's and are part of
/// the wire contract.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct KeyInfo {
    pub disk: String,
    pub path: String,
    pub name: String,
    pub alias: String,
    #[serde(rename = "serialNumber", skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,
    #[serde(rename = "subjectName", skip_serializing_if = "Option::is_none")]
    pub subject_name: Option<String>,
    /// Milliseconds since the Unix epoch: on the `ytks` key listing these two
    /// go out as a bare number, not a formatted string
    /// (`openimzo_pki::x509::epoch_millis`). Contrast
    /// `x509.get_certificate_info`'s own `validFrom`/`validTo`, which the
    /// original formats as text — a different reply shape, deliberately, and
    /// the two must not be made to agree.
    #[serde(rename = "validFrom", skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<i64>,
    #[serde(rename = "validTo", skip_serializing_if = "Option::is_none")]
    pub valid_to: Option<i64>,
    #[serde(rename = "issuerName", skip_serializing_if = "Option::is_none")]
    pub issuer_name: Option<String>,
    #[serde(rename = "publicKeyAlgName", skip_serializing_if = "Option::is_none")]
    pub public_key_alg_name: Option<String>,
    /// Not serialized: where the file actually is.
    #[serde(skip)]
    pub full_path: PathBuf,
}

pub struct Discovery {
    config: DiscoveryConfig,
}

fn with_trailing_separator(p: &Path) -> String {
    let mut s = p.to_string_lossy().into_owned();
    if !s.ends_with(std::path::MAIN_SEPARATOR) {
        s.push(std::path::MAIN_SEPARATOR);
    }
    s
}

impl Discovery {
    pub fn new(config: DiscoveryConfig) -> Self {
        Discovery { config }
    }

    pub fn config(&self) -> &DiscoveryConfig {
        &self.config
    }

    /// Every directory that may hold key files, each ending with a separator:
    /// each configured root, plus any direct child of a root named `DSKEYS`.
    /// This is the original's own removable-volume rule, and it applies
    /// to `volumes_dir` and to every entry of `extra_folders` alike — in the
    /// original, choosing a search folder in the tray menu *replaces* the
    /// volumes directory, so the two are the same thing. Deeper nesting is
    /// deliberately not searched: see `fixtures/list_disks.json`.
    pub fn list_disks(&self) -> Vec<String> {
        let mut roots: Vec<PathBuf> = Vec::new();
        if self.config.volumes_dir.is_dir() {
            roots.push(self.config.volumes_dir.clone());
        }
        for folder in &self.config.extra_folders {
            if folder.is_dir() {
                roots.push(folder.clone());
            }
        }
        let mut disks: Vec<String> = Vec::new();
        for root in &roots {
            disks.push(with_trailing_separator(root));
            let Ok(entries) = std::fs::read_dir(root) else {
                continue;
            };
            for entry in entries.flatten() {
                let child = entry.path();
                if child.file_name().map(|n| n == DSKEYS).unwrap_or(false) && child.is_dir() {
                    disks.push(with_trailing_separator(&child));
                }
            }
        }
        disks.sort();
        disks.dedup();
        disks
    }

    /// Resolves the file a request names. `path` must be `""` or `DSKEYS` —
    /// every caller checks that too, and returns the more specific `-1002`
    /// when it isn't, but this is the one place a `path` argument actually
    /// reaches a `PathBuf`, so it is enforced here as well: `PathBuf::push`
    /// with an absolute path (or, on Windows, one with a drive letter or
    /// leading separator) discards everything pushed before it, which would
    /// otherwise let a caller who forgets its own check walk the result out
    /// of `disk` for free. `name` must be a bare file stem: empty, a leading
    /// dot, a path separator, or a NUL byte is refused with `None`, so a
    /// name can never walk the result out of `disk` either.
    pub fn resolve(&self, disk: &str, path: &str, name: &str, kind: KeyKind) -> Option<PathBuf> {
        if !path.is_empty() && path != DSKEYS {
            return None;
        }
        if !self.list_disks().iter().any(|d| d == disk) {
            return None;
        }
        // `name` is a bare file stem, never a path. Refused here, in the one
        // place every caller goes through, rather than left to each plugin:
        // a name must never be able to walk the result out of `disk`, on any
        // path, whether or not the file it points at already exists.
        if name.is_empty()
            || name.starts_with('.')
            || name.contains('/')
            || name.contains('\\')
            || name.contains('\0')
        {
            return None;
        }
        let mut file = PathBuf::from(disk);
        if !path.is_empty() {
            file.push(path);
        }
        file.push(format!("{name}.{}", kind.extension()));
        Some(file)
    }

    /// Key entries on one disk, both directly in it and in its `DSKEYS`
    /// subdirectory. Unreadable or unparseable files are skipped.
    pub fn scan_disk(&self, kind: KeyKind, disk: &str) -> Vec<KeyInfo> {
        let mut out = Vec::new();
        let root = PathBuf::from(disk);
        for sub in ["", DSKEYS] {
            let dir = if sub.is_empty() { root.clone() } else { root.join(sub) };
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let file = entry.path();
                let matches_ext = file
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e.eq_ignore_ascii_case(kind.extension()))
                    .unwrap_or(false);
                if !file.is_file() || !matches_ext {
                    continue;
                }
                let Some(stem) = file.file_stem().and_then(|s| s.to_str()) else {
                    continue;
                };
                match Self::entries_of(&file, kind) {
                    Ok(entries) => {
                        for (alias, extra) in entries {
                            out.push(KeyInfo {
                                disk: disk.to_string(),
                                path: sub.to_string(),
                                name: stem.to_string(),
                                alias,
                                serial_number: extra.as_ref().map(|e| e.serial_number.clone()),
                                subject_name: extra.as_ref().map(|e| e.subject_name.clone()),
                                valid_from: extra.as_ref().map(|e| e.valid_from),
                                valid_to: extra.as_ref().map(|e| e.valid_to),
                                issuer_name: extra.as_ref().map(|e| e.issuer_name.clone()),
                                public_key_alg_name: extra.as_ref().map(|e| e.public_key_alg_name.clone()),
                                full_path: file.clone(),
                            });
                        }
                    }
                    Err(e) => tracing::debug!(file = %file.display(), error = %e, "skipping unreadable key file"),
                }
            }
        }
        out
    }

    /// Every key on every disk, deduplicated by `(full path, alias)` and in a
    /// stable order (the original's set order is not stable; ours is).
    pub fn scan(&self, kind: KeyKind) -> Vec<KeyInfo> {
        let mut by_key: BTreeMap<(String, String), KeyInfo> = BTreeMap::new();
        for disk in self.list_disks() {
            for info in self.scan_disk(kind, &disk) {
                let k = (info.full_path.to_string_lossy().into_owned(), info.alias.clone());
                match by_key.entry(k) {
                    Entry::Vacant(v) => {
                        v.insert(info);
                    }
                    Entry::Occupied(mut o) => {
                        // A key that sits directly in a folder the original also reaches
                        // through a shallower disk's `DSKEYS` child (this project's own
                        // `<F>/DSKEYS/TESTKEY.pfx` layout is exactly that) is reachable two
                        // ways at once, and which `(disk, path)` pair the original reports
                        // for it is not a rule at all: the disks are collected into an
                        // unordered set, so which of the two candidates is seen first while
                        // building the result is an artifact of that collection, not a
                        // contract — stable for one fixed search folder, but not something
                        // a rewrite can or should reproduce. We pick a fixed, principled
                        // rule instead — the disk the file actually sits in, path == "" —
                        // recorded as a deliberate deviation. Do not "simplify" this back
                        // to `or_insert`: that would make the choice depend on `list_disks`'
                        // own order instead, which is arbitrary in a different way.
                        if info.path.is_empty() && !o.get().path.is_empty() {
                            o.insert(info);
                        }
                    }
                }
            }
        }
        by_key.into_values().collect()
    }

    fn entries_of(file: &Path, kind: KeyKind) -> Result<Vec<(String, Option<YtksExtra>)>, PkiError> {
        let bytes = std::fs::read(file)?;
        match kind {
            KeyKind::Pfx => Ok(pkcs12::list_aliases(&bytes)?.into_iter().map(|a| (a, None)).collect()),
            KeyKind::Ytks => {
                let mut out = Vec::new();
                for entry in ytks::list(&bytes)? {
                    let extra = match &entry.certificate {
                        Some(cert) => {
                            let view = x509::certificate_view(cert)?;
                            let validity = &cert.tbs_certificate.validity;
                            Some(YtksExtra {
                                serial_number: view.serial_number,
                                subject_name: view.subject_name,
                                valid_from: x509::epoch_millis(x509::system_time(&validity.not_before)),
                                valid_to: x509::epoch_millis(x509::system_time(&validity.not_after)),
                                issuer_name: view.issuer_name,
                                public_key_alg_name: view
                                    .public_key
                                    .map(|p| p.key_alg_name)
                                    .unwrap_or_default(),
                            })
                        }
                        None => None,
                    };
                    out.push((entry.alias, extra));
                }
                Ok(out)
            }
        }
    }
}

#[derive(Clone, Debug)]
struct YtksExtra {
    serial_number: String,
    subject_name: String,
    valid_from: i64,
    valid_to: i64,
    issuer_name: String,
    public_key_alg_name: String,
}
