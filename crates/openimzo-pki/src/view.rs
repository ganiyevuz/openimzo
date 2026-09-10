//! JSON shapes returned to web pages, with the original's field names (Jackson, NON_NULL).
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyInfoView {
    pub key_alg_name: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignatureInfoView {
    pub sign_alg_name: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CertificateView {
    pub serial_number: String,
    pub subject_name: String,
    pub valid_from: String,
    pub valid_to: String,
    pub issuer_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<PublicKeyInfoView>,
    pub signature: SignatureInfoView,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Pkcs10InfoView {
    pub subject_name: String,
    pub public_key: PublicKeyInfoView,
    pub signature: SignatureInfoView,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignerIdView {
    pub issuer: String,
    pub subject_serial_number: String,
}
