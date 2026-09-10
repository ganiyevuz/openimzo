//! Power-on self-test. Called by the CLI now and by the engine at startup later.

use crate::hash::{gost94, Gost94};
use crate::magma::{pad_seq, unpad_seq, Magma, SBOX_D_A, SBOX_D_TEST};
use crate::ec::{CurveId, Point};
use crate::gost3410::{encode_signature, hash_to_e, public_from_private, sign, sign_with_k, verify};
use crate::keys::{KeyFamily, KeyParams, PrivateKey, PublicKey};
use der::{Decode, Encode, Tag, Tagged};
use num_bigint::BigUint;
use rand_core::OsRng;

#[derive(Debug, Clone)]
pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

fn check_hex(name: &'static str, got: &[u8], expected_hex: &str) -> Check {
    let got_hex = hex::encode(got);
    Check { name, ok: got_hex == expected_hex, detail: format!("got {got_hex}") }
}

fn big(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 16).expect("hex")
}

/// One generate-sign-verify cycle on `c`, plus the check that the signature does
/// not verify against a different hash. False if any step of it fails, so a
/// degenerate curve shows up as a failed check rather than a panic.
fn sign_verify_round_trip(c: &crate::ec::CurveParams) -> bool {
    let Ok(d) = crate::gost3410::random_scalar(&mut OsRng, &c.n) else {
        return false;
    };
    let Some(q) = public_from_private(c, &d) else {
        return false;
    };
    let hash = gost94(b"OpenImzo self-test");
    let Ok(sig) = sign(c, &d, &hash, &mut OsRng) else {
        return false;
    };
    let mut other = hash;
    other[0] ^= 0xff;
    verify(c, &q, &hash, &sig) && !verify(c, &q, &other, &sig)
}

fn signature_checks(out: &mut Vec<Check>) {
    // RFC 7091 Appendix A.1 (identical to the GOST R 34.10-2001 example).
    let c = CurveId::Test.params();
    let d = big("7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28");
    let e = big("2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5");
    let k = big("77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3");
    let expected_r = big("41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493");
    let expected_s = big("01456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40");
    let q = Point {
        x: big("7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B"),
        y: big("26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA"),
    };
    let pub_ok = public_from_private(&c, &d).as_ref() == Some(&q);
    out.push(Check { name: "rfc7091 public key", ok: pub_ok, detail: String::new() });
    let (r, s) = sign_with_k(&c, &d, &e, &k).expect("r,s nonzero");
    out.push(Check { name: "rfc7091 r", ok: r == expected_r, detail: r.to_str_radix(16) });
    out.push(Check { name: "rfc7091 s", ok: s == expected_s, detail: s.to_str_radix(16) });
    // Build a 32-byte hash whose little-endian value is e, then verify.
    let mut hash = [0u8; 32];
    let e_le = e.to_bytes_le();
    hash[..e_le.len()].copy_from_slice(&e_le);
    let ok_e = hash_to_e(&c.n, &hash) == e;
    out.push(Check { name: "rfc7091 hash_to_e", ok: ok_e, detail: String::new() });
    let sig = encode_signature(&s, &r);
    out.push(Check { name: "rfc7091 verify", ok: verify(&c, &q, &hash, &sig), detail: String::new() });
    let mut bad = sig;
    bad[63] ^= 1;
    out.push(Check { name: "rfc7091 verify rejects tampered", ok: !verify(&c, &q, &hash, &bad), detail: String::new() });

    for id in [CurveId::A, CurveId::B, CurveId::C] {
        let c = id.params();
        let g_ok = c.is_on_curve(&c.g) && c.base_mul(&c.n).is_none();
        out.push(Check { name: "curve generator and order", ok: g_ok, detail: id.name().to_string() });
        out.push(Check { name: "sign/verify round trip", ok: sign_verify_round_trip(&c), detail: id.name().to_string() });
    }
}

pub fn run() -> Vec<Check> {
    let mut out = Vec::with_capacity(40);
    out.push(check_hex("gost94 empty", &gost94(b""), "981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0"));
    out.push(check_hex("gost94 'a'", &gost94(b"a"), "e74c52dd282183bf37af0079c9f78055715a103f17e3133ceff1aacf2f403011"));
    out.push(check_hex("gost94 'abc'", &gost94(b"abc"), "b285056dbf18d7392d7677369524dd14747459ed8143997e163b2986f92fd42c"));
    out.push(check_hex("gost94 'message digest'", &gost94(b"message digest"), "bc6041dd2aa401ebfa6e9886734174febdb4729aa972d60f549ac39b29721ba0"));
    out.push(check_hex("gost94 fox", &gost94(b"The quick brown fox jumps over the lazy dog"), "9004294a361a508c586fe53d1f1b02746765e71b765472786e4770d565830a76"));
    out.push(check_hex("gost94 32 bytes", &gost94(b"This is message, length=32 bytes"), "2cefc2f7b7bdc514e18ea57fa74ff357e7fa17d652c75f69cb1be7893ede48eb"));
    out.push(check_hex("gost94 64 x a", &gost94(&[b'a'; 64]), "351e9effed44763b11597bc3286b0d0e06bc62dfffea7ee0d3d3a892d33c88a7"));
    out.push(check_hex("gost94 1000 x a", &gost94(&[b'a'; 1000]), "cfd707497028e7afefdf80f823a0e0171bcdf5ee402be94e448acb8fb4ae58f3"));
    let mut t = Gost94::with_sbox(&SBOX_D_TEST);
    t.update(b"");
    out.push(check_hex("gost94 D-TEST empty", &t.finalize(), "ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d"));
    let mut t = Gost94::with_sbox(&SBOX_D_TEST);
    t.update(b"a");
    out.push(check_hex("gost94 D-TEST 'a'", &t.finalize(), "d42c539e367c66e9c88a801f6649349c21871b4344c6a573f849fdce62f314dd"));

    // Magma: encrypt/decrypt round trip and padding round trip (the hash vectors above
    // already prove the cipher core bit-exact, because the hash runs Magma with the same S-box).
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let m = Magma::new(&key, &SBOX_D_A);
    let plain = b"OpenImzo magma check";
    let padded = pad_seq(plain);
    let ct = m.ecb_encrypt(&padded).expect("padded");
    let back = m.ecb_decrypt(&ct).and_then(|p| unpad_seq(&p)).expect("round trip");
    out.push(Check { name: "magma ecb+seqpad round trip", ok: back == plain, detail: format!("ct len {}", ct.len()) });
    out.push(Check { name: "magma ct differs from pt", ok: ct[..8] != padded[..8], detail: String::new() });

    signature_checks(&mut out);
    key_checks(&mut out);
    apikey_checks(&mut out);
    out
}

fn apikey_checks(out: &mut Vec<Check>) {
    let vectors = [
        ("localhost", "96D0C1491615C82B9A54D9989779DF825B690748224C2B04F500F370D51827CE2644D8D4A82C18184D73AB8530BB8ED537269603F61DB0D03D2104ABF789970B"),
        ("127.0.0.1", "A7BCFA5D490B351BE0754130DF03A068F855DB4333D43921125B9CF2670EF6A40370C646B90401955E1F7BC9CDBF59CE0B2C5467D820BE189C845D0B79CFC96F"),
        ("null", "E0A205EC4E7B78BBB56AFF83A733A1BB9FD39D562E67978CC5E7D73B0951DB1954595A20672A63332535E13CC6EC1E1FC8857BB09E0855D7E76E411B6FA16E9D"),
    ];
    let q_ok = CurveId::A.params().is_on_curve(&crate::apikey::fixed_public_key());
    out.push(Check { name: "apikey public key on curve A", ok: q_ok, detail: String::new() });
    for (domain, key) in vectors {
        out.push(Check { name: "apikey valid", ok: crate::apikey::verify_domain(domain, key), detail: domain.to_string() });
    }
    out.push(Check { name: "apikey rejects other domain", ok: !crate::apikey::verify_domain("example.uz", vectors[0].1), detail: String::new() });
    let mut flipped = vectors[0].1.to_string();
    flipped.replace_range(127..128, if &vectors[0].1[127..] == "B" { "C" } else { "B" });
    out.push(Check { name: "apikey rejects tampered", ok: !crate::apikey::verify_domain("localhost", &flipped), detail: String::new() });
}

fn key_checks(out: &mut Vec<Check>) {
    for family in [KeyFamily::Ozmst, KeyFamily::Ozdst] {
        let key = PrivateKey::generate(family, CurveId::A, &mut OsRng).expect("generate");
        let spki = key.public_key().to_spki_der().expect("spki");
        let back = PublicKey::from_spki_der(&spki).expect("parse spki");
        out.push(Check { name: "spki round trip", ok: back == key.public_key(), detail: family.algorithm_name().into() });

        let p8 = key.to_pkcs8_der().expect("pkcs8");
        let back = PrivateKey::from_pkcs8_der(&p8).expect("parse pkcs8");
        out.push(Check { name: "pkcs8 (SEC1) round trip", ok: back.d == key.d && back.curve == key.curve, detail: family.algorithm_name().into() });

        // The original itself always writes SEC1 style: a bare named-curve OID as the
        // algorithm parameters, not a `SEQUENCE{keyParamSet, digestParamSet}` (GOST style,
        // which the original's own KeyFactory rejects when writing back out — confirmed by the
        // Task 13 interop harness against the real jars).
        let pki = pkcs8::PrivateKeyInfo::from_der(&p8).expect("pki");
        let params = pki.algorithm.parameters.expect("params");
        let named: der::asn1::ObjectIdentifier = params.decode_as().expect("named curve OID");
        out.push(Check {
            name: "pkcs8 carries bare named-curve OID (SEC1 style)",
            ok: params.tag() == Tag::ObjectIdentifier && named == family.param_oid(CurveId::A).expect("oid"),
            detail: String::new(),
        });

        // 1-element GOST style (what Java re-encodes) must parse too.
        let one = KeyParams { key_param_set: family.param_oid(CurveId::A).expect("oid"), digest_param_set: None, enc_param_set: None }.to_der().expect("der");
        let mut d_le = key.d_be32();
        d_le.reverse();
        let pki1 = pkcs8::PrivateKeyInfo {
            algorithm: spki::AlgorithmIdentifierRef { oid: family.key_oid(), parameters: Some(der::asn1::AnyRef::try_from(one.as_slice()).expect("any")) },
            private_key: &d_le,
            public_key: None,
        };
        let back = PrivateKey::from_pkcs8_der(&pki1.to_der().expect("der")).expect("parse 1-element");
        out.push(Check { name: "pkcs8 (1-element) parses", ok: back.d == key.d, detail: String::new() });

        // SEC1 style with named-curve OID in the algorithm parameters (what BC writes for new keys).
        let named = family.param_oid(CurveId::A).expect("oid").to_der().expect("oid der");
        let d_be = key.d_be32();
        let sec1 = SelftestEcPrivateKey {
            version: 1,
            private_key: der::asn1::OctetStringRef::new(&d_be).expect("octets"),
            parameters: Some(der::asn1::AnyRef::try_from(named.as_slice()).expect("any")),
            public_key: None,
        }
        .to_der()
        .expect("sec1");
        let pki2 = pkcs8::PrivateKeyInfo {
            algorithm: spki::AlgorithmIdentifierRef { oid: family.key_oid(), parameters: Some(der::asn1::AnyRef::try_from(named.as_slice()).expect("any")) },
            private_key: &sec1,
            public_key: None,
        };
        let back = PrivateKey::from_pkcs8_der(&pki2.to_der().expect("der")).expect("parse sec1");
        out.push(Check { name: "pkcs8 (SEC1) parses", ok: back.d == key.d, detail: String::new() });
    }
}

#[derive(der::Sequence)]
struct SelftestEcPrivateKey<'a> {
    version: u8,
    private_key: der::asn1::OctetStringRef<'a>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    parameters: Option<der::asn1::AnyRef<'a>>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    public_key: Option<der::asn1::BitStringRef<'a>>,
}
