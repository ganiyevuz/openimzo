//! Short-lived state a site refers to by id: which key file was loaded, a
//! freshly generated key pair waiting to be saved, and a password the user
//! allowed us to remember. The private key and chain a password opens are
//! never kept here: every consumer re-reads the file itself, so caching them
//! would only be a second copy of key material with nothing to read it back.

use openimzo_crypto::PrivateKey;
use parking_lot::Mutex;
use rand::RngCore;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

pub const DEFAULT_TTL: Duration = Duration::from_secs(24 * 60 * 60);
pub const PASSWORD_TTL_REMEMBERED: Duration = Duration::from_secs(6 * 60 * 60);
pub const PASSWORD_TTL_TRANSIENT: Duration = Duration::from_secs(60);

/// The most sessions held at once. A local caller can create one with no
/// user interaction at all, so the map needs a ceiling; at the cap a sweep
/// runs first and the oldest entries go if that frees nothing.
pub const MAX_SESSIONS: usize = 4096;

pub const FIXED_IDCARD: &str = "idcard";
pub const FIXED_BAIKEY: &str = "baikey";
pub const FIXED_CKC: &str = "ckc";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionType {
    KeyPair,
    PfxKeyStore,
    YtksKeyStore,
    IdcardKeyStore,
    BaikTokenKeyStore,
    UzguardTokenKeyStore,
    CkcStore,
}

impl SessionType {
    /// The exact strings the original puts in the `type` field of `load_key`.
    pub fn wire_name(self) -> &'static str {
        match self {
            SessionType::KeyPair => "KEY_PAIR",
            SessionType::PfxKeyStore => "PFX_KEY_STORE",
            SessionType::YtksKeyStore => "YTKS_KEY_STORE",
            SessionType::IdcardKeyStore => "IDCARD_EIMZO_KEY_STORE",
            SessionType::BaikTokenKeyStore => "BAIK_TOKEN_KEY_STORE",
            SessionType::UzguardTokenKeyStore => "UZGUARD_TOKEN_KEY_STORE",
            SessionType::CkcStore => "CKC_STORE",
        }
    }
}

#[derive(Clone, Default)]
pub struct SessionData {
    pub kind: Option<SessionType>,
    /// Key file this session refers to, for PFX and YKS sessions.
    pub key_store_path: Option<PathBuf>,
    pub key_store_alias: Option<String>,
    /// A generated key pair waiting to be saved (`pkcs10.generate_keypair`).
    pub key_pair: Option<PrivateKey>,
}

impl SessionData {
    pub fn of_type(kind: SessionType) -> Self {
        SessionData { kind: Some(kind), ..Default::default() }
    }
}

struct Entry {
    data: SessionData,
    expires: Instant,
    password: Option<String>,
    password_expires: Instant,
}

impl Drop for Entry {
    fn drop(&mut self) {
        if let Some(p) = &mut self.password {
            p.zeroize();
        }
    }
}

#[derive(Default)]
pub struct Sessions {
    entries: Mutex<HashMap<String, Entry>>,
}

fn fixed_type(id: &str) -> Option<SessionType> {
    match id {
        FIXED_IDCARD => Some(SessionType::IdcardKeyStore),
        FIXED_BAIKEY => Some(SessionType::BaikTokenKeyStore),
        FIXED_CKC => Some(SessionType::CkcStore),
        _ => None,
    }
}

/// The entry for `id`, or `None` if it has expired — expired entries are
/// dropped on the way out so their key material and password go with them.
fn live_entry<'a>(
    entries: &'a mut HashMap<String, Entry>,
    id: &str,
    now: Instant,
) -> Option<&'a mut Entry> {
    if entries.get(id)?.expires <= now {
        entries.remove(id);
        return None;
    }
    entries.get_mut(id)
}

impl Sessions {
    pub fn new() -> Self {
        Sessions::default()
    }

    fn new_id() -> String {
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    pub fn put(&self, data: SessionData) -> String {
        self.put_with_ttl(data, DEFAULT_TTL)
    }

    pub fn put_with_ttl(&self, data: SessionData, ttl: Duration) -> String {
        let id = Self::new_id();
        let now = Instant::now();
        let mut entries = self.entries.lock();
        entries.retain(|_, e| e.expires > now);
        while entries.len() >= MAX_SESSIONS {
            // Still full after the sweep above: make room by evicting
            // whichever entry expires soonest.
            let Some(oldest) = entries.iter().min_by_key(|(_, e)| e.expires).map(|(id, _)| id.clone()) else {
                break;
            };
            entries.remove(&oldest);
        }
        entries.insert(id.clone(), Entry { data, expires: now + ttl, password: None, password_expires: now });
        id
    }

    pub fn get(&self, id: &str) -> Option<SessionData> {
        if let Some(kind) = fixed_type(id) {
            return Some(SessionData::of_type(kind));
        }
        let mut entries = self.entries.lock();
        let entry = entries.get(id)?;
        if entry.expires <= Instant::now() {
            entries.remove(id);
            return None;
        }
        Some(entry.data.clone())
    }

    /// Replaces the stored data, keeping the entry's expiry and password.
    pub fn update(&self, id: &str, data: SessionData) {
        if fixed_type(id).is_some() {
            return;
        }
        let now = Instant::now();
        let mut entries = self.entries.lock();
        if let Some(entry) = live_entry(&mut entries, id, now) {
            entry.data = data;
        }
    }

    pub fn type_of(&self, id: &str) -> Option<SessionType> {
        self.get(id).and_then(|d| d.kind)
    }

    pub fn remove(&self, id: &str) {
        if fixed_type(id).is_some() {
            return;
        }
        self.entries.lock().remove(id);
    }

    pub fn remember_password(&self, id: &str, password: &str, ttl: Duration) {
        if fixed_type(id).is_some() {
            return;
        }
        let now = Instant::now();
        let mut entries = self.entries.lock();
        let Some(entry) = live_entry(&mut entries, id, now) else {
            return;
        };
        if let Some(old) = &mut entry.password {
            old.zeroize();
        }
        entry.password = Some(password.to_string());
        entry.password_expires = now + ttl;
    }

    /// The remembered password, if the session is still alive and the password's
    /// own shorter deadline has not passed. Expired material is wiped here rather
    /// than merely hidden.
    pub fn cached_password(&self, id: &str) -> Option<Zeroizing<String>> {
        if fixed_type(id).is_some() {
            return None;
        }
        let now = Instant::now();
        let mut entries = self.entries.lock();
        let entry = live_entry(&mut entries, id, now)?;
        if entry.password_expires <= now {
            if let Some(p) = &mut entry.password {
                p.zeroize();
            }
            entry.password = None;
            return None;
        }
        entry.password.clone().map(Zeroizing::new)
    }

    pub fn expire_password(&self, id: &str) {
        if fixed_type(id).is_some() {
            return;
        }
        let now = Instant::now();
        let mut entries = self.entries.lock();
        if let Some(entry) = live_entry(&mut entries, id, now) {
            if let Some(p) = &mut entry.password {
                p.zeroize();
            }
            entry.password = None;
        }
    }

    /// Zeroes and drops every session's cached password right now, without
    /// touching the sessions themselves or their own expiry. `sweep` and
    /// `expire_password` each wipe one password once its own deadline
    /// passes; this is for the person asking, from Settings, to forget
    /// every remembered password immediately regardless of how much of its
    /// TTL is left.
    pub fn clear_all_passwords(&self) {
        let mut entries = self.entries.lock();
        for entry in entries.values_mut() {
            if let Some(p) = &mut entry.password {
                p.zeroize();
            }
            entry.password = None;
        }
    }

    /// Drops expired entries and wipes passwords whose own deadline has passed,
    /// so an expired password does not sit in memory until the next read.
    /// Phase 2B calls this on a timer.
    pub fn sweep(&self) {
        let now = Instant::now();
        let mut entries = self.entries.lock();
        entries.retain(|_, e| e.expires > now);
        for entry in entries.values_mut() {
            if entry.password_expires <= now {
                if let Some(p) = &mut entry.password {
                    p.zeroize();
                }
                entry.password = None;
            }
        }
    }

    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
