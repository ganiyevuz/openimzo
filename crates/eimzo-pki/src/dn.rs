//! Distinguished names in the string form BouncyCastle 1.50 produces (`X509Name.toString()`)
//! and parses (`BCStyle`), plus the original's own RDN lookup rule.

use crate::{PkiError, Result};
use const_oid::ObjectIdentifier;
use der::asn1::{Any, Ia5StringRef, PrintableStringRef, Utf8StringRef};
use der::{Decode, Encode, Tag, Tagged};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};

/// (OID, display symbol) — BouncyCastle X509Name.DefaultSymbols.
const SYMBOLS: &[(&str, &str)] = &[
    ("2.5.4.6", "C"),
    ("2.5.4.10", "O"),
    ("2.5.4.12", "T"),
    ("2.5.4.11", "OU"),
    ("2.5.4.3", "CN"),
    ("2.5.4.7", "L"),
    ("2.5.4.8", "ST"),
    ("2.5.4.5", "SERIALNUMBER"),
    ("1.2.840.113549.1.9.1", "E"),
    ("0.9.2342.19200300.100.1.25", "DC"),
    ("0.9.2342.19200300.100.1.1", "UID"),
    ("2.5.4.9", "STREET"),
    ("2.5.4.4", "SURNAME"),
    ("2.5.4.42", "GIVENNAME"),
    ("2.5.4.43", "INITIALS"),
    ("2.5.4.44", "GENERATION"),
    ("2.5.4.45", "UniqueIdentifier"),
    ("2.5.4.46", "DN"),
    ("2.5.4.65", "Pseudonym"),
    ("2.5.4.16", "PostalAddress"),
    ("2.5.4.41", "Name"),
    ("1.3.6.1.5.5.7.9.1", "DateOfBirth"),
    ("1.3.6.1.5.5.7.9.2", "PlaceOfBirth"),
    ("1.3.6.1.5.5.7.9.3", "Gender"),
    ("1.3.6.1.5.5.7.9.4", "CountryOfCitizenship"),
    ("1.3.6.1.5.5.7.9.5", "CountryOfResidence"),
    ("1.3.36.8.3.14", "NameAtBirth"),
    ("2.5.4.17", "PostalCode"),
    ("2.5.4.15", "BusinessCategory"),
    ("2.5.4.20", "TelephoneNumber"),
    ("1.2.840.113549.1.9.2", "unstructuredName"),
    ("1.2.840.113549.1.9.8", "unstructuredAddress"),
];

/// (lower-case attribute name accepted on input, OID) — BouncyCastle BCStyle.DefaultLookUp.
const LOOKUP: &[(&str, &str)] = &[
    ("c", "2.5.4.6"), ("o", "2.5.4.10"), ("t", "2.5.4.12"), ("ou", "2.5.4.11"), ("cn", "2.5.4.3"),
    ("l", "2.5.4.7"), ("st", "2.5.4.8"), ("sn", "2.5.4.5"), ("serialnumber", "2.5.4.5"),
    ("street", "2.5.4.9"), ("emailaddress", "1.2.840.113549.1.9.1"), ("e", "1.2.840.113549.1.9.1"),
    ("dc", "0.9.2342.19200300.100.1.25"), ("uid", "0.9.2342.19200300.100.1.1"), ("surname", "2.5.4.4"),
    ("givenname", "2.5.4.42"), ("initials", "2.5.4.43"), ("generation", "2.5.4.44"),
    ("unstructuredaddress", "1.2.840.113549.1.9.8"), ("unstructuredname", "1.2.840.113549.1.9.2"),
    ("uniqueidentifier", "2.5.4.45"), ("dn", "2.5.4.46"), ("pseudonym", "2.5.4.65"),
    ("postaladdress", "2.5.4.16"), ("nameofbirth", "1.3.36.8.3.14"), ("countryofcitizenship", "1.3.6.1.5.5.7.9.4"),
    ("countryofresidence", "1.3.6.1.5.5.7.9.5"), ("gender", "1.3.6.1.5.5.7.9.3"), ("placeofbirth", "1.3.6.1.5.5.7.9.2"),
    ("dateofbirth", "1.3.6.1.5.5.7.9.1"), ("postalcode", "2.5.4.17"), ("businesscategory", "2.5.4.15"),
    ("telephonenumber", "2.5.4.20"), ("name", "2.5.4.41"),
];

/// Attributes BCStyle encodes as PrintableString instead of UTF8String.
const PRINTABLE: &[&str] = &["2.5.4.6", "2.5.4.5", "2.5.4.46", "2.5.4.20"];
/// Attributes BCStyle encodes as IA5String.
const IA5: &[&str] = &["1.2.840.113549.1.9.1", "0.9.2342.19200300.100.1.25"];

pub fn attribute_display_name(oid: &ObjectIdentifier) -> String {
    let s = oid.to_string();
    SYMBOLS.iter().find(|(o, _)| *o == s).map(|(_, n)| (*n).to_string()).unwrap_or(s)
}

fn attribute_oid_from_name(name: &str) -> Result<ObjectIdentifier> {
    let lower = name.trim().to_ascii_lowercase();
    if let Some((_, o)) = LOOKUP.iter().find(|(n, _)| *n == lower) {
        return ObjectIdentifier::new(o).map_err(|e| PkiError::Asn1(e.to_string()));
    }
    ObjectIdentifier::new(name.trim()).map_err(|_| PkiError::Unsupported(format!("unknown attribute {name}")))
}

/// Decodes the common directory string types; anything else is `#` + hex of its DER.
pub fn value_to_string(value: &Any) -> String {
    let text = match value.tag() {
        Tag::Utf8String => value.decode_as::<Utf8StringRef>().ok().map(|s| s.to_string()),
        Tag::PrintableString => value.decode_as::<PrintableStringRef>().ok().map(|s| s.to_string()),
        Tag::Ia5String => value.decode_as::<Ia5StringRef>().ok().map(|s| s.to_string()),
        Tag::TeletexString => value.decode_as::<der::asn1::TeletexStringRef>().ok().map(|s| s.to_string()),
        Tag::BmpString => value.decode_as::<der::asn1::BmpString>().ok().map(|s| s.to_string()),
        _ => None,
    };
    match text {
        Some(t) => escape_value(&t),
        None => format!("#{}", hex::encode(value.to_der().unwrap_or_default())),
    }
}

fn escape_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for (i, ch) in v.chars().enumerate() {
        if matches!(ch, ',' | '"' | '\\' | '+' | '=' | '<' | '>' | ';') || (i == 0 && (ch == '#' || ch == ' ')) {
            out.push('\\');
        }
        out.push(ch);
    }
    if out.ends_with(' ') {
        out.insert(out.len() - 1, '\\');
    }
    out
}

/// BouncyCastle `X509Name.toString()`: RDNs in encoded order, `SYMBOL=value`, `,` between RDNs, `+` inside one.
pub fn dn_to_string(name: &Name) -> String {
    let mut parts = Vec::new();
    for rdn in name.0.iter() {
        let avas: Vec<String> = rdn
            .0
            .iter()
            .map(|ava| format!("{}={}", attribute_display_name(&ava.oid), value_to_string(&ava.value)))
            .collect();
        parts.push(avas.join("+"));
    }
    parts.join(",")
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(n) = chars.next() {
                out.push(n);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Splits on unescaped `sep`, keeping escapes for later `unescape`.
fn split_unescaped(s: &str, sep: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut escaped = false;
    for c in s.chars() {
        if escaped {
            cur.push('\\');
            cur.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == sep {
            parts.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    parts.push(cur);
    parts
}

fn ava_from_string(s: &str) -> Result<AttributeTypeAndValue> {
    let (name, raw) = s.split_once('=').ok_or_else(|| PkiError::Unsupported(format!("bad RDN {s}")))?;
    let oid = attribute_oid_from_name(name)?;
    let value_text = unescape(raw.trim());
    let value = if let Some(hex_der) = value_text.strip_prefix('#') {
        let bytes = hex::decode(hex_der).map_err(|e| PkiError::Asn1(e.to_string()))?;
        Any::from_der(&bytes)?
    } else {
        let o = oid.to_string();
        if PRINTABLE.contains(&o.as_str()) {
            Any::encode_from(&PrintableStringRef::new(&value_text)?)?
        } else if IA5.contains(&o.as_str()) {
            Any::encode_from(&Ia5StringRef::new(&value_text)?)?
        } else {
            Any::encode_from(&Utf8StringRef::new(&value_text)?)?
        }
    };
    Ok(AttributeTypeAndValue { oid, value })
}

/// BCStyle parsing of e.g. `CN=Test User,O=Org,C=UZ,1.2.860.3.16.1.2=123,SERIALNUMBER=X` (order kept).
pub fn dn_from_string(s: &str) -> Result<Name> {
    let mut rdns = Vec::new();
    for rdn_text in split_unescaped(s.trim(), ',') {
        if rdn_text.trim().is_empty() {
            continue;
        }
        let mut avas = Vec::new();
        for ava_text in split_unescaped(&rdn_text, '+') {
            avas.push(ava_from_string(&ava_text)?);
        }
        rdns.push(RelativeDistinguishedName::try_from(avas)?);
    }
    Ok(RdnSequence(rdns))
}

/// The original's own DN split rule: cut before every `,<spaces><Name|OID>=`.
pub fn dn_split(s: &str) -> Vec<String> {
    let bytes: Vec<char> = s.chars().collect();
    let mut cuts = vec![0usize];
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == ',' {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j].is_whitespace() {
                j += 1;
            }
            let start = j;
            let alpha = j < bytes.len() && bytes[j].is_ascii_alphabetic();
            let numeric = j < bytes.len() && (bytes[j].is_ascii_digit() || bytes[j] == '.');
            while j < bytes.len() && ((alpha && bytes[j].is_ascii_alphabetic()) || (numeric && (bytes[j].is_ascii_digit() || bytes[j] == '.'))) {
                j += 1;
            }
            if j > start && j < bytes.len() && bytes[j] == '=' {
                cuts.push(i);
            }
        }
        i += 1;
    }
    let mut parts = Vec::new();
    for (k, &start) in cuts.iter().enumerate() {
        let end = cuts.get(k + 1).copied().unwrap_or(bytes.len());
        let from = if start == 0 { 0 } else { start + 1 };
        parts.push(bytes[from..end].iter().collect::<String>().trim().to_string());
    }
    parts
}

/// The original's own RDN lookup rule: first RDN text that *starts with* `field`, value after `=`.
pub fn dn_get(dn_string: &str, field: &str) -> Option<String> {
    dn_split(dn_string)
        .into_iter()
        .find(|part| part.starts_with(field))
        .and_then(|part| part.split_once('=').map(|(_, v)| v.to_string()))
}
