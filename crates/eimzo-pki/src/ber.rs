//! Canonicalize BER into DER.
//!
//! BouncyCastle 1.50's streaming CMS generator (`CMSSignedDataGenerator`), which the original
//! signs through, writes BER, not DER: the outer `ContentInfo` `SEQUENCE` and several elements
//! nested inside it use indefinite length (a length octet of `0x80`, terminated later by two zero
//! octets), and the encapsulated content is a *constructed* `OCTET STRING` wrapping one or more
//! primitive segments rather than a single primitive `OCTET STRING`. The `der`/`cms` crates this
//! crate otherwise relies on are strict DER decoders and reject all of that outright. This module
//! re-encodes such a BER TLV stream as canonical DER so it can be handed to them.
//!
//! `fixtures/java-attached.p7` is a real sample of exactly this BER shape, kept so the
//! canonicalization below can be checked against something the strict decoders reject.

use crate::{PkiError, Result};

const MAX_DEPTH: u32 = 64;

/// One parsed element. `tag` holds the raw identifier octets from the input, preserved verbatim —
/// except when canonicalization retags a constructed `OCTET STRING`/`BIT STRING` as primitive.
/// `class` and `tag_number` are decoded from those octets for the universal-type checks below
/// (SEQUENCE/SET ordering is never touched; `OCTET STRING`/`BIT STRING` fragments are merged).
struct Elem {
    tag: Vec<u8>,
    class: u8,
    tag_number: u64,
    body: Body,
}

enum Body {
    Primitive(Vec<u8>),
    Constructed(Vec<Elem>),
}

/// Re-encodes a single BER-encoded TLV — any mix of definite and indefinite lengths, and any
/// fragmented constructed `OCTET STRING`/`BIT STRING` — as canonical DER. Rejects trailing garbage,
/// truncated input, an oversized declared length (checked without ever overflowing `usize`), and
/// nesting deeper than 64 levels (the 65th nested element is rejected); never panics on malformed
/// input, however adversarial.
pub fn to_der(input: &[u8]) -> Result<Vec<u8>> {
    let mut pos = 0usize;
    let elem = parse_element(input, &mut pos, 0)?;
    if pos != input.len() {
        return Err(PkiError::Asn1("BER: trailing garbage after the top-level element".into()));
    }
    let canon = canonicalize(elem)?;
    Ok(encode_element(&canon))
}

fn parse_element(input: &[u8], pos: &mut usize, depth: u32) -> Result<Elem> {
    if depth >= MAX_DEPTH {
        return Err(PkiError::Asn1("BER: nesting too deep".into()));
    }
    let first = *input.get(*pos).ok_or_else(|| PkiError::Asn1("BER: truncated (expected a tag)".into()))?;
    let class = first & 0xC0;
    let constructed = first & 0x20 != 0;
    let low_tag = first & 0x1F;
    let mut tag_end = *pos + 1;
    let tag_number: u64 = if low_tag == 0x1F {
        let mut n: u64 = 0;
        let mut octets = 0u32;
        loop {
            let b = *input.get(tag_end).ok_or_else(|| PkiError::Asn1("BER: truncated high-tag-number form".into()))?;
            n = (n << 7) | (b & 0x7F) as u64;
            tag_end += 1;
            octets += 1;
            if b & 0x80 == 0 {
                break;
            }
            if octets > 9 {
                return Err(PkiError::Asn1("BER: tag number too large".into()));
            }
        }
        n
    } else {
        low_tag as u64
    };
    let tag_bytes = input[*pos..tag_end].to_vec();
    *pos = tag_end;

    let len_byte = *input.get(*pos).ok_or_else(|| PkiError::Asn1("BER: truncated (expected a length)".into()))?;
    *pos += 1;

    if len_byte == 0x80 {
        if !constructed {
            return Err(PkiError::Asn1("BER: indefinite length on a primitive element".into()));
        }
        let mut children = Vec::new();
        loop {
            let b0 = *input.get(*pos).ok_or_else(|| PkiError::Asn1("BER: missing end-of-contents".into()))?;
            if b0 == 0x00 {
                let b1 = *input.get(*pos + 1).ok_or_else(|| PkiError::Asn1("BER: truncated end-of-contents".into()))?;
                if b1 != 0x00 {
                    return Err(PkiError::Asn1("BER: malformed end-of-contents".into()));
                }
                *pos += 2;
                break;
            }
            children.push(parse_element(input, pos, depth + 1)?);
        }
        return Ok(Elem { tag: tag_bytes, class, tag_number, body: Body::Constructed(children) });
    }

    let len: usize = if len_byte & 0x80 == 0 {
        len_byte as usize
    } else {
        let n = (len_byte & 0x7F) as usize;
        if n == 0 || n > 8 {
            return Err(PkiError::Asn1("BER: unsupported long-form length".into()));
        }
        // Never add an attacker-controlled count to `*pos` before comparing: check via the
        // remaining length instead, so this can't overflow regardless of how large `n` or `*pos`
        // are (both are actually small here, but the same guard is used below for `len`, which is
        // decoded from up to 8 attacker-controlled octets and can be as large as `u64::MAX`).
        if input.len().checked_sub(*pos).is_none_or(|rem| n > rem) {
            return Err(PkiError::Asn1("BER: truncated length octets".into()));
        }
        let mut v: u64 = 0;
        for &b in &input[*pos..*pos + n] {
            v = (v << 8) | b as u64;
        }
        *pos += n;
        // `v` can be up to `u64::MAX`; never truncate it silently into a (possibly narrower) `usize`.
        usize::try_from(v).map_err(|_| PkiError::Asn1("BER: length too large".into()))?
    };

    if input.len().checked_sub(*pos).is_none_or(|rem| len > rem) {
        return Err(PkiError::Asn1("BER: truncated content".into()));
    }
    let content = &input[*pos..*pos + len];
    *pos += len;

    if constructed {
        let mut cpos = 0usize;
        let mut children = Vec::new();
        while cpos < content.len() {
            children.push(parse_element(content, &mut cpos, depth + 1)?);
        }
        Ok(Elem { tag: tag_bytes, class, tag_number, body: Body::Constructed(children) })
    } else {
        Ok(Elem { tag: tag_bytes, class, tag_number, body: Body::Primitive(content.to_vec()) })
    }
}

fn is_universal(e: &Elem, number: u64) -> bool {
    e.class == 0x00 && e.tag_number == number
}

/// Concatenates the (already-canonicalized, so already-flattened if nested) primitive segments of
/// a constructed `OCTET STRING` into one primitive `OCTET STRING`'s content.
fn flatten_octet_string(children: &[Elem]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for c in children {
        if !is_universal(c, 4) {
            return Err(PkiError::Asn1("BER: constructed OCTET STRING has a non-OCTET-STRING segment".into()));
        }
        match &c.body {
            Body::Primitive(bytes) => out.extend_from_slice(bytes),
            Body::Constructed(_) => return Err(PkiError::Asn1("BER: OCTET STRING segment was not flattened".into())),
        }
    }
    Ok(out)
}

/// Concatenates the segments of a constructed `BIT STRING`, keeping the unused-bits octet only
/// from the first segment and dropping the (redundant) unused-bits octet of every later one.
fn flatten_bit_string(children: &[Elem]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut first = true;
    for c in children {
        if !is_universal(c, 3) {
            return Err(PkiError::Asn1("BER: constructed BIT STRING has a non-BIT-STRING segment".into()));
        }
        let bytes = match &c.body {
            Body::Primitive(bytes) => bytes,
            Body::Constructed(_) => return Err(PkiError::Asn1("BER: BIT STRING segment was not flattened".into())),
        };
        let unused = *bytes.first().ok_or_else(|| PkiError::Asn1("BER: BIT STRING segment missing its unused-bits octet".into()))?;
        if first {
            out.push(unused);
            first = false;
        }
        out.extend_from_slice(&bytes[1..]);
    }
    if first {
        out.push(0);
    }
    Ok(out)
}

/// X.690 §11.6 DER ordering for `SET OF`: compare encodings octet by octet, treating the missing
/// trailing octets of the shorter encoding as `0x00`.
fn cmp_der(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        match x.cmp(&y) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

fn canonicalize(e: Elem) -> Result<Elem> {
    let Elem { tag, class, tag_number, body } = e;
    let children = match body {
        Body::Primitive(bytes) => return Ok(Elem { tag, class, tag_number, body: Body::Primitive(bytes) }),
        Body::Constructed(children) => children,
    };
    let mut canon_children = Vec::with_capacity(children.len());
    for c in children {
        canon_children.push(canonicalize(c)?);
    }

    if class == 0x00 && tag_number == 4 {
        let flat = flatten_octet_string(&canon_children)?;
        return Ok(Elem { tag: vec![0x04], class: 0x00, tag_number: 4, body: Body::Primitive(flat) });
    }
    if class == 0x00 && tag_number == 3 {
        let flat = flatten_bit_string(&canon_children)?;
        return Ok(Elem { tag: vec![0x03], class: 0x00, tag_number: 3, body: Body::Primitive(flat) });
    }
    if class == 0x00 && tag_number == 17 {
        // SET / SET OF: reorder by each (already-canonical) child's own encoding.
        let mut keyed: Vec<(Vec<u8>, Elem)> = canon_children.into_iter().map(|c| (encode_element(&c), c)).collect();
        keyed.sort_by(|(ka, _), (kb, _)| cmp_der(ka, kb));
        canon_children = keyed.into_iter().map(|(_, c)| c).collect();
    }
    // SEQUENCE, and everything else (context/application/private-tagged wrappers): order preserved.

    Ok(Elem { tag, class, tag_number, body: Body::Constructed(canon_children) })
}

fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let mut bytes = Vec::new();
    let mut n = len as u64;
    while n > 0 {
        bytes.push((n & 0xFF) as u8);
        n >>= 8;
    }
    bytes.reverse();
    let mut out = Vec::with_capacity(1 + bytes.len());
    out.push(0x80 | bytes.len() as u8);
    out.extend(bytes);
    out
}

fn encode_element(e: &Elem) -> Vec<u8> {
    let content: Vec<u8> = match &e.body {
        Body::Primitive(bytes) => bytes.clone(),
        Body::Constructed(children) => {
            let mut out = Vec::new();
            for c in children {
                out.extend(encode_element(c));
            }
            out
        }
    };
    let mut out = Vec::with_capacity(e.tag.len() + 9 + content.len());
    out.extend_from_slice(&e.tag);
    out.extend(encode_length(content.len()));
    out.extend(content);
    out
}
