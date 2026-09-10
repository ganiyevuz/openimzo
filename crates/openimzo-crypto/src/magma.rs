//! GOST 28147-89 ("Magma") exactly as the original implements it, ECB only.

use crate::{CryptoError, Result};

const BLOCK_SIZE: usize = 8;

/// S-box "D-A" (= id-GostR3411-94-CryptoProParamSet). Used by the hash, YTKS, QR-key.
pub const SBOX_D_A: [u8; 128] = [
    10, 4, 5, 6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11, 15,
    5, 15, 4, 0, 2, 13, 11, 9, 1, 7, 6, 3, 12, 14, 10, 8,
    7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5, 2, 6, 10, 8, 13,
    4, 10, 7, 12, 0, 15, 2, 8, 14, 1, 6, 5, 13, 11, 9, 3,
    7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0, 14, 15, 13, 3, 5,
    7, 6, 2, 4, 13, 9, 15, 0, 10, 1, 5, 11, 8, 14, 12, 3,
    13, 14, 4, 1, 7, 0, 5, 10, 3, 12, 8, 15, 6, 2, 9, 11,
    1, 3, 10, 9, 5, 11, 4, 15, 8, 6, 7, 14, 13, 0, 2, 12,
];

/// S-box "D-TEST" (= id-GostR3411-94-TestParamSet). Only for the `-TEST` variants.
pub const SBOX_D_TEST: [u8; 128] = [
    4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3,
    14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9,
    5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11,
    7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3,
    6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2,
    4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14,
    13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12,
    1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12,
];

#[derive(Clone)]
pub struct Magma {
    key: [u32; 8],
    sbox: &'static [u8; 128],
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

impl Magma {
    pub fn new(key: &[u8; 32], sbox: &'static [u8; 128]) -> Self {
        let mut k = [0u32; 8];
        for (i, w) in k.iter_mut().enumerate() {
            *w = le32(&key[i * 4..i * 4 + 4]);
        }
        Magma { key: k, sbox }
    }

    fn step(&self, n1: u32, k: u32) -> u32 {
        let cm = n1.wrapping_add(k);
        let mut om = 0u32;
        for m in 0..8 {
            let nibble = ((cm >> (4 * m)) & 15) as usize;
            om |= (self.sbox[m * 16 + nibble] as u32) << (4 * m);
        }
        om.rotate_left(11)
    }

    pub fn encrypt_block(&self, input: &[u8; 8]) -> [u8; 8] {
        let mut n1 = le32(&input[0..4]);
        let mut n2 = le32(&input[4..8]);
        let k = &self.key;
        for _ in 0..3 {
            #[allow(clippy::needless_range_loop)]
            for j in 0..8 {
                let t = n2 ^ self.step(n1, k[j]);
                n2 = n1;
                n1 = t;
            }
        }
        #[allow(clippy::needless_range_loop)]
        for j in (1..8).rev() {
            let t = n2 ^ self.step(n1, k[j]);
            n2 = n1;
            n1 = t;
        }
        let n2_final = n2 ^ self.step(n1, k[0]);
        let mut out = [0u8; 8];
        out[0..4].copy_from_slice(&n1.to_le_bytes());
        out[4..8].copy_from_slice(&n2_final.to_le_bytes());
        out
    }

    pub fn decrypt_block(&self, input: &[u8; 8]) -> [u8; 8] {
        let mut n1 = le32(&input[0..4]);
        let mut n2 = le32(&input[4..8]);
        let k = &self.key;
        #[allow(clippy::needless_range_loop)]
        for j in 0..8 {
            let t = n2 ^ self.step(n1, k[j]);
            n2 = n1;
            n1 = t;
        }
        for round in 0..3 {
            let mut j: i32 = 7;
            while j >= 0 && !(round == 2 && j == 0) {
                let t = n2 ^ self.step(n1, k[j as usize]);
                n2 = n1;
                n1 = t;
                j -= 1;
            }
        }
        let n2_final = n2 ^ self.step(n1, k[0]);
        let mut out = [0u8; 8];
        out[0..4].copy_from_slice(&n1.to_le_bytes());
        out[4..8].copy_from_slice(&n2_final.to_le_bytes());
        out
    }

    /// ECB over a buffer whose length is a multiple of 8 (no padding here).
    /// ECB over a buffer whose length is a multiple of 8 (no padding here).
    pub fn ecb_encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if !data.len().is_multiple_of(BLOCK_SIZE) {
            return Err(CryptoError::Padding);
        }
        let mut out = Vec::with_capacity(data.len());
        for i in (0..data.len()).step_by(BLOCK_SIZE) {
            let block: &[u8; 8] = (&data[i..i + BLOCK_SIZE]).try_into().expect("slice of BLOCK_SIZE bytes");
            out.extend_from_slice(&self.encrypt_block(block));
        }
        Ok(out)
    }

    pub fn ecb_decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if !data.len().is_multiple_of(BLOCK_SIZE) {
            return Err(CryptoError::Padding);
        }
        let mut out = Vec::with_capacity(data.len());
        for i in (0..data.len()).step_by(BLOCK_SIZE) {
            let block: &[u8; 8] = (&data[i..i + BLOCK_SIZE]).try_into().expect("slice of BLOCK_SIZE bytes");
            out.extend_from_slice(&self.decrypt_block(block));
        }
        Ok(out)
    }
}

/// The original's own GOST PKCS#7-style padding: 1..=8 bytes holding the sequence 1,2,3,...,padSize.
pub fn pad_seq(data: &[u8]) -> Vec<u8> {
    let pad = 8 - (data.len() % 8);
    let mut out = Vec::with_capacity(data.len() + pad);
    out.extend_from_slice(data);
    for i in 1..=pad {
        out.push(i as u8);
    }
    out
}

pub fn unpad_seq(data: &[u8]) -> Result<Vec<u8>> {
    let last = *data.last().ok_or(CryptoError::Padding)? as usize;
    if !(1..=8).contains(&last) || data.len() < last {
        return Err(CryptoError::Padding);
    }
    let body = data.len() - last;
    for (i, expected) in (1..=last).enumerate() {
        if data[body + i] as usize != expected {
            return Err(CryptoError::Padding);
        }
    }
    Ok(data[..body].to_vec())
}
