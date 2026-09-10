//! Key families (OZDST = legacy OID family, OZMST = 2024 OID family; same math),
//! SPKI / PKCS#8 encodings and key generation.

use crate::ec::{CurveId, Point};
use crate::gost3410::{public_from_private, random_scalar, sign, verify};
use crate::oid;
use crate::{CryptoError, Result};
use const_oid::ObjectIdentifier;
use der::asn1::{Any, AnyRef, BitString, BitStringRef, OctetString, OctetStringRef, UintRef};
use der::{Decode, Encode, Tag, Tagged};
use num_bigint::BigUint;
use num_traits::Zero;
use rand_core::{CryptoRng, RngCore};
use spki::{AlgorithmIdentifierOwned, AlgorithmIdentifierRef, SubjectPublicKeyInfoOwned};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyFamily {
    Ozdst,
    Ozmst,
}

impl KeyFamily {
    pub fn algorithm_name(self) -> &'static str {
        match self {
            KeyFamily::Ozdst => "OZDST-1092-2009-2",
            KeyFamily::Ozmst => "OZMST-286-2024-2",
        }
    }

    pub fn from_algorithm_name(name: &str) -> Option<Self> {
        match name.to_ascii_uppercase().as_str() {
            "OZDST-1092-2009-2" => Some(KeyFamily::Ozdst),
            "OZMST-286-2024-2" => Some(KeyFamily::Ozmst),
            _ => None,
        }
    }

    pub fn key_oid(self) -> ObjectIdentifier {
        match self {
            KeyFamily::Ozdst => oid::KEY_OZDST,
            KeyFamily::Ozmst => oid::KEY_OZMST,
        }
    }

    pub fn sig_oid(self) -> ObjectIdentifier {
        match self {
            KeyFamily::Ozdst => oid::SIG_OZDST_A,
            KeyFamily::Ozmst => oid::SIG_OZMST_A,
        }
    }

    pub fn digest_oid(self) -> ObjectIdentifier {
        match self {
            KeyFamily::Ozdst => oid::DIGEST_OZDST_A,
            KeyFamily::Ozmst => oid::DIGEST_OZMST_A,
        }
    }

    pub fn from_key_oid(o: &ObjectIdentifier) -> Option<Self> {
        if *o == oid::KEY_OZDST {
            Some(KeyFamily::Ozdst)
        } else if *o == oid::KEY_OZMST {
            Some(KeyFamily::Ozmst)
        } else {
            None
        }
    }

    pub fn from_sig_oid(o: &ObjectIdentifier) -> Option<Self> {
        if *o == oid::SIG_OZDST_A {
            Some(KeyFamily::Ozdst)
        } else if *o == oid::SIG_OZMST_A {
            Some(KeyFamily::Ozmst)
        } else {
            None
        }
    }

    pub fn param_oid(self, curve: CurveId) -> Result<ObjectIdentifier> {
        Ok(match (self, curve) {
            (KeyFamily::Ozdst, CurveId::A) => oid::OZDST_PARAM_A,
            (KeyFamily::Ozdst, CurveId::B) => oid::OZDST_PARAM_B,
            (KeyFamily::Ozdst, CurveId::C) => oid::OZDST_PARAM_C,
            (KeyFamily::Ozmst, CurveId::A) => oid::OZMST_PARAM_A,
            (KeyFamily::Ozmst, CurveId::B) => oid::OZMST_PARAM_B,
            (KeyFamily::Ozmst, CurveId::C) => oid::OZMST_PARAM_C,
            (_, CurveId::Test) => return Err(CryptoError::Unsupported("test curve has no OID".into())),
        })
    }

    pub fn curve_from_param_oid(self, o: &ObjectIdentifier) -> Option<CurveId> {
        let o = *o;
        match self {
            KeyFamily::Ozdst => {
                if o == oid::OZDST_PARAM_A || o == oid::OZDST_PARAM_XCHA {
                    Some(CurveId::A)
                } else if o == oid::OZDST_PARAM_B {
                    Some(CurveId::B)
                } else if o == oid::OZDST_PARAM_C || o == oid::OZDST_PARAM_XCHB {
                    Some(CurveId::C)
                } else {
                    None
                }
            }
            KeyFamily::Ozmst => {
                if o == oid::OZMST_PARAM_A || o == oid::OZMST_PARAM_D {
                    Some(CurveId::A)
                } else if o == oid::OZMST_PARAM_B || o == oid::OZMST_PARAM_E {
                    Some(CurveId::B)
                } else if o == oid::OZMST_PARAM_C || o == oid::OZMST_PARAM_XCHB {
                    Some(CurveId::C)
                } else {
                    None
                }
            }
        }
    }

    /// Curve resolution when the family is not known in advance (SEC1 named-curve OIDs).
    pub fn family_and_curve_from_param_oid(o: &ObjectIdentifier) -> Option<(KeyFamily, CurveId)> {
        KeyFamily::Ozdst
            .curve_from_param_oid(o)
            .map(|c| (KeyFamily::Ozdst, c))
            .or_else(|| KeyFamily::Ozmst.curve_from_param_oid(o).map(|c| (KeyFamily::Ozmst, c)))
    }

    pub fn curve_name(self, curve: CurveId) -> String {
        format!("{}-{}", self.algorithm_name(), curve.name())
    }
}

/// `SEQUENCE { keyParamSet OID, digestParamSet OID OPTIONAL, encParamSet OID OPTIONAL }`.
/// The original writes 1 element in SPKI and expects >= 2 in PKCS#8.
#[derive(Clone, Debug, der::Sequence)]
pub struct KeyParams {
    pub key_param_set: ObjectIdentifier,
    #[asn1(optional = "true")]
    pub digest_param_set: Option<ObjectIdentifier>,
    #[asn1(optional = "true")]
    pub enc_param_set: Option<ObjectIdentifier>,
}

/// SEC1 ECPrivateKey (RFC 5915), the form BouncyCastle writes for freshly generated keys.
#[derive(der::Sequence)]
struct EcPrivateKey<'a> {
    version: u8,
    private_key: OctetStringRef<'a>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    parameters: Option<AnyRef<'a>>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    public_key: Option<BitStringRef<'a>>,
}

fn be32(v: &BigUint) -> Result<[u8; 32]> {
    let b = v.to_bytes_be();
    if b.len() > 32 {
        return Err(CryptoError::InvalidKey("scalar longer than 32 bytes".into()));
    }
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(&b);
    Ok(out)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub family: KeyFamily,
    pub curve: CurveId,
    pub point: Point,
}

impl PublicKey {
    /// 64 bytes: x little-endian 32 || y little-endian 32.
    pub fn xy_le64(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        let mut x = be32(&self.point.x).expect("x < p");
        let mut y = be32(&self.point.y).expect("y < p");
        x.reverse();
        y.reverse();
        out[..32].copy_from_slice(&x);
        out[32..].copy_from_slice(&y);
        out
    }

    pub fn from_xy_le64(family: KeyFamily, curve: CurveId, bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(CryptoError::Encoding(format!("public key must be 64 bytes, got {}", bytes.len())));
        }
        let point = Point { x: BigUint::from_bytes_le(&bytes[..32]), y: BigUint::from_bytes_le(&bytes[32..]) };
        if !curve.params().is_on_curve(&point) {
            return Err(CryptoError::InvalidKey("point is not on the curve".into()));
        }
        Ok(PublicKey { family, curve, point })
    }

    pub fn to_spki(&self) -> Result<SubjectPublicKeyInfoOwned> {
        let params = KeyParams { key_param_set: self.family.param_oid(self.curve)?, digest_param_set: None, enc_param_set: None };
        let key_octets = OctetString::new(self.xy_le64().to_vec())?.to_der()?;
        Ok(SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned { oid: self.family.key_oid(), parameters: Some(Any::encode_from(&params)?) },
            subject_public_key: BitString::from_bytes(&key_octets)?,
        })
    }

    pub fn to_spki_der(&self) -> Result<Vec<u8>> {
        Ok(self.to_spki()?.to_der()?)
    }

    pub fn from_spki(spki: &SubjectPublicKeyInfoOwned) -> Result<Self> {
        let family = KeyFamily::from_key_oid(&spki.algorithm.oid)
            .ok_or_else(|| CryptoError::Unsupported(format!("key algorithm {}", spki.algorithm.oid)))?;
        let params = spki
            .algorithm
            .parameters
            .as_ref()
            .ok_or_else(|| CryptoError::Encoding("missing key parameters".into()))?;
        let kp: KeyParams = params.decode_as()?;
        let curve = family
            .curve_from_param_oid(&kp.key_param_set)
            .ok_or_else(|| CryptoError::Unsupported(format!("curve {}", kp.key_param_set)))?;
        let octets = OctetStringRef::from_der(spki.subject_public_key.raw_bytes())?;
        Self::from_xy_le64(family, curve, octets.as_bytes())
    }

    pub fn from_spki_der(der_bytes: &[u8]) -> Result<Self> {
        Self::from_spki(&SubjectPublicKeyInfoOwned::from_der(der_bytes)?)
    }

    pub fn verify(&self, hash: &[u8; 32], sig: &[u8]) -> bool {
        verify(&self.curve.params(), &self.point, hash, sig)
    }
}

/// SECURITY: `d` is the secret scalar. It is **not** zeroized on drop: `num_bigint::BigUint`
/// owns its digit storage internally and exposes no in-place scrubbing, so overwriting the
/// field itself (`self.d = BigUint::zero()`) would only replace the reference, not scrub the
/// old allocation.
///
/// This comment used to defer that to "when `ec.rs` moves to `crypto-bigint`". That move has
/// happened, and it deliberately did not fix this: `ec.rs` keeps `BigUint` at its public
/// boundary — `Point`, `CurveParams` and every caller above them are unchanged — and converts
/// to fixed-width `U256` inside `mul` instead. Scrubbing `d` therefore means changing the type
/// `PrivateKey` carries, which cascades through `gost3410`, the rest of this module and
/// everything above it. It is a deliberate open item, not a pending migration, and the
/// reader should not expect some later commit to have quietly closed it.
///
/// What *is* zeroized: every byte buffer this crate and its callers derive from `d` — the
/// PKCS#8 encoding in `to_pkcs8_der`, the QR-key export material in `pki::qrkey::encode`,
/// decrypted key blobs — is scrubbed explicitly at its call site. So is the per-signature
/// nonce's own 32-byte draw, in `gost3410::random_scalar`, which is a different secret from
/// `d` but the one whose leakage is worth the most to an attacker.
#[derive(Clone)]
pub struct PrivateKey {
    pub family: KeyFamily,
    pub curve: CurveId,
    pub d: BigUint,
    pub public: Point,
}

impl core::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PrivateKey({} curve {})", self.family.algorithm_name(), self.curve.name())
    }
}

impl PrivateKey {
    pub fn from_scalar(family: KeyFamily, curve: CurveId, d: BigUint) -> Result<Self> {
        let c = curve.params();
        if d.is_zero() || d >= c.n {
            return Err(CryptoError::InvalidKey("private scalar out of range".into()));
        }
        let public = public_from_private(&c, &d).ok_or_else(|| CryptoError::InvalidKey("degenerate key".into()))?;
        Ok(PrivateKey { family, curve, d, public })
    }

    pub fn generate<R: RngCore + CryptoRng>(family: KeyFamily, curve: CurveId, rng: &mut R) -> Result<Self> {
        let d = random_scalar(rng, &curve.params().n)?;
        Self::from_scalar(family, curve, d)
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey { family: self.family, curve: self.curve, point: self.public.clone() }
    }

    pub fn sign<R: RngCore + CryptoRng>(&self, hash: &[u8; 32], rng: &mut R) -> Result<[u8; 64]> {
        sign(&self.curve.params(), &self.d, hash, rng)
    }

    pub fn d_be32(&self) -> [u8; 32] {
        be32(&self.d).expect("d < n")
    }

    /// PKCS#8 in "SEC1 style": this is the format the original
    /// itself writes for every PFX it saves (`generate_keypair` → `save_pfx`). `AlgorithmIdentifier`'s
    /// `parameters` is the bare named-curve OID (no wrapping `SEQUENCE`); `privateKey` is a SEC1
    /// `ECPrivateKey` (RFC 5915): version 1, `d` BIG-endian, `[0]` the same named-curve OID (redundant,
    /// ignored on read), `[1]` the public key as the SPKI's `BIT STRING { OCTET STRING (64 bytes) }`.
    /// The "GOST style" (`SEQUENCE { keyParamSet, digestParamSet }`, `d` little-endian) is
    /// only ever produced by other Uzbek tools, never by the original; `from_pkcs8_der` still accepts
    /// it (and the SEC1 style) on read. Confirmed against the original's own `KeyFactory` via the
    /// interop harness (Task 13): re-encoding with the GOST style is rejected with
    /// `InvalidKeySpecException: encoded key spec not recognised`; this SEC1 style is accepted.
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>> {
        let param_oid = self.family.param_oid(self.curve)?;
        let param_oid_der = param_oid.to_der()?;
        let key_octets = OctetString::new(self.public_key().xy_le64().to_vec())?.to_der()?;
        let mut d_be = self.d_be32();
        let ec = EcPrivateKey {
            version: 1,
            private_key: OctetStringRef::new(&d_be)?,
            parameters: Some(AnyRef::try_from(param_oid_der.as_slice())?),
            public_key: Some(BitStringRef::from_bytes(&key_octets)?),
        };
        let ec_der = ec.to_der()?;
        d_be.zeroize();
        let pki = pkcs8::PrivateKeyInfo {
            algorithm: AlgorithmIdentifierRef { oid: self.family.key_oid(), parameters: Some(AnyRef::try_from(param_oid_der.as_slice())?) },
            private_key: &ec_der,
            public_key: None,
        };
        Ok(pki.to_der()?)
    }

    /// Accepts every format the original itself can produce.
    pub fn from_pkcs8_der(der_bytes: &[u8]) -> Result<Self> {
        let pki = pkcs8::PrivateKeyInfo::from_der(der_bytes)?;
        let family = KeyFamily::from_key_oid(&pki.algorithm.oid)
            .ok_or_else(|| CryptoError::Unsupported(format!("key algorithm {}", pki.algorithm.oid)))?;
        match pki.algorithm.parameters {
            Some(p) if p.tag() == Tag::Sequence => {
                // GOST style, 1..3 element parameter sequence, d little-endian.
                let kp: KeyParams = p.decode_as()?;
                let curve = family
                    .curve_from_param_oid(&kp.key_param_set)
                    .ok_or_else(|| CryptoError::Unsupported(format!("curve {}", kp.key_param_set)))?;
                Self::from_scalar(family, curve, BigUint::from_bytes_le(pki.private_key))
            }
            Some(p) if p.tag() == Tag::ObjectIdentifier => {
                let named: ObjectIdentifier = p.decode_as()?;
                let (_, curve) = KeyFamily::family_and_curve_from_param_oid(&named)
                    .ok_or_else(|| CryptoError::Unsupported(format!("named curve {named}")))?;
                let ec = EcPrivateKey::from_der(pki.private_key)?;
                Self::from_scalar(family, curve, BigUint::from_bytes_be(ec.private_key.as_bytes()))
            }
            _ => {
                // NULL or absent: SEC1 structure carrying its own named curve, or a bare INTEGER (curve A).
                if let Ok(ec) = EcPrivateKey::from_der(pki.private_key) {
                    let named: ObjectIdentifier = ec
                        .parameters
                        .ok_or_else(|| CryptoError::Encoding("SEC1 key without parameters".into()))?
                        .decode_as()?;
                    let (_, curve) = KeyFamily::family_and_curve_from_param_oid(&named)
                        .ok_or_else(|| CryptoError::Unsupported(format!("named curve {named}")))?;
                    Self::from_scalar(family, curve, BigUint::from_bytes_be(ec.private_key.as_bytes()))
                } else {
                    let int = UintRef::from_der(pki.private_key)?;
                    Self::from_scalar(family, CurveId::A, BigUint::from_bytes_be(int.as_bytes()))
                }
            }
        }
    }
}

/// Helper for callers that only have the algorithm identifier of a signature.
pub fn family_of_signature_algorithm(alg: &AlgorithmIdentifierOwned) -> Option<KeyFamily> {
    KeyFamily::from_sig_oid(&alg.oid)
}

/// Builds `AlgorithmIdentifier { oid, NULL }` as the original emits for signatures and digests.
pub fn algorithm_with_null(o: ObjectIdentifier) -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned { oid: o, parameters: Some(Any::from(AnyRef::NULL)) }
}
