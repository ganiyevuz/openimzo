//! Password byte conventions, matching the original.

/// BMPString (UTF-16BE) followed by a 2-byte zero terminator; empty password -> `[0, 0]`.
pub fn bmp_with_terminator(password: &str) -> Vec<u8> {
    let mut v: Vec<u8> = password.encode_utf16().flat_map(|u| u.to_be_bytes()).collect();
    v.extend([0u8, 0u8]);
    v
}

/// UTF-16BE without terminator (YTKS-2).
pub fn utf16_be(password: &str) -> Vec<u8> {
    password.encode_utf16().flat_map(|u| u.to_be_bytes()).collect()
}

/// BouncyCastle `PKCS5PasswordToBytes`: the low 8 bits of every UTF-16 code unit (not UTF-8).
pub fn pkcs5_bytes(password: &str) -> Vec<u8> {
    password.encode_utf16().map(|u| (u & 0xff) as u8).collect()
}
