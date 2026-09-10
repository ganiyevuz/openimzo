//! Every OID the core needs.
use const_oid::ObjectIdentifier;

pub const KEY_OZDST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.860.3.15.1.1.2.1");
pub const KEY_OZMST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.860.3.15.2.1.2.1");
pub const KEY_OZDST_ALG1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.860.3.15.1.1.1.1");

pub const OZDST_PARAM_A: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.860.3.15.1.1.2.1.1");
pub const OZDST_PARAM_B: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.860.3.15.1.1.2.1.2");
pub const OZDST_PARAM_C: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.860.3.15.1.1.2.1.3");
pub const OZDST_PARAM_D: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.860.3.15.1.1.2.1.4");
pub const OZDST_PARAM_XCHA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.860.3.15.1.1.2.1.5");
pub const OZDST_PARAM_XCHB: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.860.3.15.1.1.2.1.6");

pub const OZMST_PARAM_A: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.860.3.15.2.1.2.1.1");
pub const OZMST_PARAM_B: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.860.3.15.2.1.2.1.2");
pub const OZMST_PARAM_C: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.860.3.15.2.1.2.1.3");
pub const OZMST_PARAM_D: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.860.3.15.2.1.2.1.4");
/// Registered twice in the original (E and XchA); its parameters resolve to curve B.
pub const OZMST_PARAM_E: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.860.3.15.2.1.2.1.5");
pub const OZMST_PARAM_XCHB: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.860.3.15.2.1.2.1.6");

pub const SIG_OZDST_A: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.860.3.15.1.1.2.2.2.2");
pub const SIG_OZMST_A: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.860.3.15.2.1.2.2.2.2");
pub const SIG_OZDST_ALG1_A: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.860.3.15.1.1.1.2.2.2");

pub const DIGEST_OZDST_A: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.860.3.15.1.3.2.1.1");
pub const DIGEST_OZMST_A: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.860.3.15.2.3.2.1.1");

pub const X500_INN: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.860.3.16.1.1");
pub const X500_PINFL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.860.3.16.1.2");

pub const YTKS2_ENCRYPTED_PRIVATE_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.860.3.2.10.1");
pub const YTKS2_ENCRYPTED_PRIVATE_KEY_OLD: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.860.1.4.1.100.1.1.1.1");
pub const TEMP_CERT_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.860.3.2.10.2");

/// The names the original's own crypto provider registers for these OIDs.
/// Only the curve-A parameter sets have names; every other OID has none
/// there, and both the original and we fall back to the OID's own text.
pub fn algorithm_name(oid: &ObjectIdentifier) -> Option<&'static str> {
    if *oid == SIG_OZDST_ALG1_A {
        Some("OZDST-1106-2009-2-AwithOZDST-1092-2009-1")
    } else if *oid == SIG_OZDST_A {
        Some("OZDST-1106-2009-2-AwithOZDST-1092-2009-2")
    } else if *oid == SIG_OZMST_A {
        Some("OZMST-285-2024-2-AwithOZMST-286-2024-2")
    } else if *oid == KEY_OZDST_ALG1 {
        Some("OZDST-1092-2009-1")
    } else if *oid == KEY_OZDST {
        Some("OZDST-1092-2009-2")
    } else if *oid == KEY_OZMST {
        Some("OZMST-286-2024-2")
    } else {
        None
    }
}
