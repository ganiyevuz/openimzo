//! The original's message bundles, embedded verbatim. Sites match on these
//! strings, so they are copied byte-for-byte from the app we replace.

use std::collections::HashMap;

const RU: &str = include_str!("../resources/messages_ru.properties");
const UZ: &str = include_str!("../resources/messages_uz.properties");

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Lang {
    #[default]
    Ru,
    Uz,
}

impl Lang {
    pub fn code(self) -> &'static str {
        match self {
            Lang::Ru => "ru",
            Lang::Uz => "uz",
        }
    }

    /// The original accepts exactly "ru" and "uz" in `app.change_ui_lang`.
    pub fn from_code(code: &str) -> Option<Self> {
        match code {
            "ru" => Some(Lang::Ru),
            "uz" => Some(Lang::Uz),
            _ => None,
        }
    }
}

/// The languages the app's own chrome is written in — its menu bar, its
/// window, and the two pages this project serves on `127.0.0.1`.
///
/// Deliberately a different type from [`Lang`], which it sits next to so the
/// difference is impossible to miss. `Lang` is a wire contract: it is what
/// `app.change_ui_lang` accepts and what every reply a website reads is
/// written in, and the original admits exactly `ru` and `uz` there — so
/// widening it would change what every integrated site sees. `UiLang` is
/// ours. It has English, because the person using the app and the websites
/// it answers are not the same audience, and nothing a website reads is
/// ever written in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum UiLang {
    #[default]
    Ru,
    Uz,
    En,
}

impl UiLang {
    pub fn code(self) -> &'static str {
        match self {
            UiLang::Ru => "ru",
            UiLang::Uz => "uz",
            UiLang::En => "en",
        }
    }

    /// The three codes the macOS shell's own `AppLanguage` spells. Anything
    /// else is `None`, and the caller keeps whatever it already had.
    pub fn from_code(code: &str) -> Option<Self> {
        match code {
            "ru" => Some(UiLang::Ru),
            "uz" => Some(UiLang::Uz),
            "en" => Some(UiLang::En),
            _ => None,
        }
    }
}

/// One argument for a `%s` / `%d` placeholder.
#[derive(Clone, Debug)]
pub enum Arg {
    S(String),
    D(i64),
}

impl From<&str> for Arg {
    fn from(v: &str) -> Self {
        Arg::S(v.to_string())
    }
}

impl From<String> for Arg {
    fn from(v: String) -> Self {
        Arg::S(v)
    }
}

impl From<i64> for Arg {
    fn from(v: i64) -> Self {
        Arg::D(v)
    }
}

pub struct Messages {
    ru: HashMap<String, String>,
    uz: HashMap<String, String>,
}

/// Java `.properties`: `key=value`, `\n` and `\t` escapes, `#`/`!` comments,
/// no line continuations in these two files (verified when they were copied).
fn parse(src: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in src.lines() {
        let line = line.trim_start();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let mut out = String::with_capacity(value.len());
        let mut chars = value.chars();
        while let Some(c) = chars.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some(other) => out.push(other),
                None => {}
            }
        }
        map.insert(key.trim().to_string(), out);
    }
    map
}

impl Default for Messages {
    fn default() -> Self {
        Self::load()
    }
}

impl Messages {
    pub fn load() -> Self {
        Messages { ru: parse(RU), uz: parse(UZ) }
    }

    /// The raw text for a key. Falls back to Russian, then to the key itself,
    /// so a missing translation degrades to something a human can still read.
    pub fn get<'a>(&'a self, lang: Lang, key: &'a str) -> &'a str {
        let table = match lang {
            Lang::Ru => &self.ru,
            Lang::Uz => &self.uz,
        };
        table
            .get(key)
            .or_else(|| self.ru.get(key))
            .map(String::as_str)
            .unwrap_or(key)
    }

    /// Substitutes `%s`, `%d`, `%x`, and `%X` left to right, as `String.format` does for
    /// the argument shapes these messages actually use. Width and zero-padding are supported
    /// for hex formats (e.g., `%04X`). Surplus placeholders are left in place; surplus arguments
    /// are ignored.
    pub fn format(&self, lang: Lang, key: &str, args: &[Arg]) -> String {
        let template = self.get(lang, key);
        let mut out = String::with_capacity(template.len() + 16);
        let mut rest = template;
        let mut next = args.iter();

        while let Some(pos) = rest.find('%') {
            let (before, tail) = rest.split_at(pos);
            out.push_str(before);

            // tail starts with '%'
            let bytes = tail.as_bytes();
            if bytes.len() < 2 {
                // Just a trailing '%'
                out.push('%');
                rest = &tail[1..];
                continue;
            }

            let mut idx = 1; // skip the '%'
            let mut zero_flag = false;
            let mut width: usize = 0;

            // Check for optional '0' flag
            if idx < bytes.len() && bytes[idx] == b'0' {
                zero_flag = true;
                idx += 1;
            }

            // Check for optional width (digits)
            while idx < bytes.len() && bytes[idx].is_ascii_digit() {
                width = width * 10 + (bytes[idx] - b'0') as usize;
                idx += 1;
            }

            if idx >= bytes.len() {
                // No conversion character
                out.push('%');
                rest = &tail[1..];
                continue;
            }

            let conversion = bytes[idx] as char;
            idx += 1;

            // Check for valid conversion characters
            match conversion {
                '%' => {
                    out.push('%');
                    rest = &tail[idx..];
                }
                's' | 'd' | 'x' | 'X' => {
                    match next.next() {
                        Some(arg) => {
                            let formatted = match (conversion, arg) {
                                ('s', Arg::S(v)) => v.clone(),
                                ('s', Arg::D(v)) => v.to_string(),
                                ('d', Arg::D(v)) => v.to_string(),
                                ('d', Arg::S(v)) => v.clone(),
                                ('x', Arg::D(v)) => format!("{:x}", v),
                                ('X', Arg::D(v)) => format!("{:X}", v),
                                ('x', Arg::S(v)) => v.clone(),
                                ('X', Arg::S(v)) => v.clone(),
                                _ => unreachable!(),
                            };

                            // Apply zero-padding if needed
                            if zero_flag && width > 0 && formatted.len() < width {
                                let padding = width - formatted.len();
                                for _ in 0..padding {
                                    out.push('0');
                                }
                            }
                            out.push_str(&formatted);
                            rest = &tail[idx..];
                        }
                        None => {
                            // No argument, leave the specifier in place verbatim
                            out.push_str(&tail[..idx]);
                            rest = &tail[idx..];
                        }
                    }
                }
                _ => {
                    // Unrecognized conversion character
                    out.push('%');
                    rest = &tail[1..];
                }
            }
        }
        out.push_str(rest);
        out
    }
}
