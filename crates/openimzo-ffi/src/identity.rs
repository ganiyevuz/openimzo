//! Who a key belongs to, read from the one string that is always available.
//!
//! A PFX's certificate cannot be read without its password, so for the common case the alias is
//! the only thing there is — and an alias is not a name, it is a DN:
//! `cn=test user,name=test,surname=user,1.2.860.3.16.1.2=12345678901234,serialnumber=test0001`.
//! Until this existed, every locked PFX row in the Keys list said "details need the password"
//! while the person's own name sat unread in the alias beside it.
//!
//! The attribute-to-meaning mapping is the original's, taken from its own code rather than
//! guessed at: `CN` is the full name (it labels this "Ф.И.О."), `1.2.860.3.16.1.2` is PINFL
//! ("ПИН ФЛ"), `UID` is a person's own tax number ("Физ.ИНН"), `1.2.860.3.16.1.1` is an
//! organisation's ("Юр.ИНН"), and `O` is the organisation. The last three are worth keeping
//! straight: an individual's tax number and an organisation's are different attributes, and
//! collapsing them into one "TIN" would label an organisation's number as the person's.

use chrono::{Local, NaiveDateTime, TimeZone};
use openimzo_pki::dn::dn_split;

use crate::types::KeyIdentity;

/// The format the original writes into an alias, and the one this app shows everywhere else:
/// `2025.02.03 11:09:32`. Local time, because the original formats it with a default-timezone
/// `SimpleDateFormat` and this has to read back what that wrote.
const ALIAS_TIME_FORMAT: &str = "%Y.%m.%d %H:%M:%S";

/// One attribute's value, case-insensitively.
///
/// Case matters here in a way it does not in a certificate: an alias is written lowercase
/// (`cn=`, `serialnumber=`) while a subject DN read back from a certificate is written upper
/// (`CN=`, `SERIALNUMBER=`), and this reads both.
fn attribute(parts: &[String], name: &str) -> String {
    for part in parts {
        let Some((key, value)) = part.split_once('=') else { continue };
        if key.trim().eq_ignore_ascii_case(name) {
            return value.trim().to_string();
        }
    }
    String::new()
}

/// Takes each field from `subject_dn` when the certificate has been read, and from `alias`
/// otherwise — field by field rather than all-or-nothing, since an alias sometimes carries an
/// attribute the certificate's subject does not, and the reverse.
pub fn identity_from(alias: &str, subject_dn: &str) -> KeyIdentity {
    let from_cert = dn_split(subject_dn);
    let from_alias = dn_split(alias);
    let pick = |name: &str| {
        let value = attribute(&from_cert, name);
        if value.is_empty() { attribute(&from_alias, name) } else { value }
    };

    let organisation = pick("O");
    KeyIdentity {
        common_name: pick("CN"),
        surname: pick("SURNAME"),
        given_name: pick("NAME"),
        position: pick("T"),
        country: pick("C"),
        pinfl: pick("1.2.860.3.16.1.2"),
        tin_individual: pick("UID"),
        tin_organisation: pick("1.2.860.3.16.1.1"),
        alias_serial_number: pick("SERIALNUMBER"),
        // The presence of an organisation is the whole test, deliberately — not the presence of
        // an organisation tax number. The two national tax-number attributes are what the whole
        // classification would otherwise rest on, and a certificate carrying one for a reason
        // this project has not seen would be silently misfiled. An `O` is unambiguous.
        is_organisation: !organisation.is_empty(),
        organisation,
    }
}

/// `validfrom` / `validto` as milliseconds since the epoch, when the alias carries them.
///
/// The original writes these into aliases for keys it generates itself, in the format above.
/// A key whose alias has neither — which is most of them — gets `(None, None)`, and the caller
/// falls back to the certificate's own validity, which for a PFX means waiting for a password.
pub fn alias_validity_millis(alias: &str) -> (Option<i64>, Option<i64>) {
    let parts = dn_split(alias);
    (parse_alias_time(&attribute(&parts, "validfrom")), parse_alias_time(&attribute(&parts, "validto")))
}

fn parse_alias_time(text: &str) -> Option<i64> {
    if text.is_empty() {
        return None;
    }
    let naive = NaiveDateTime::parse_from_str(text, ALIAS_TIME_FORMAT).ok()?;
    // `single()` and not `earliest()`: on the hour a clock goes back, a wall-clock time happens
    // twice and there is no honest answer, so this reports no validity rather than picking one
    // and being an hour out. `None` costs a person nothing — the certificate is still the
    // authority, and this was only ever a shortcut past needing its password.
    Local.from_local_datetime(&naive).single().map(|dt| dt.timestamp_millis())
}
