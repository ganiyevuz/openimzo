//! GOST R 34.11-94, in both of the variants the original implements under the Uzbek OIDs.

use crate::magma::{Magma, SBOX_D_A};

const C2: [u8; 32] = [
    0, 0xff, 0, 0xff, 0, 0xff, 0, 0xff, 0xff, 0, 0xff, 0, 0xff, 0, 0xff, 0,
    0, 0xff, 0xff, 0, 0xff, 0, 0, 0xff, 0xff, 0, 0, 0, 0xff, 0xff, 0, 0xff,
];

#[derive(Clone)]
pub struct Gost94 {
    sbox: &'static [u8; 128],
    h: [u8; 32],
    sum: [u8; 32],
    buf: [u8; 32],
    off: usize,
    count: u64,
}

impl Default for Gost94 {
    fn default() -> Self {
        Self::new()
    }
}

impl Gost94 {
    /// D-A S-box: the one every consumer in E-IMZO uses.
    pub fn new() -> Self {
        Self::with_sbox(&SBOX_D_A)
    }

    pub fn with_sbox(sbox: &'static [u8; 128]) -> Self {
        Gost94 { sbox, h: [0; 32], sum: [0; 32], buf: [0; 32], off: 0, count: 0 }
    }

    pub fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.update_byte(b);
        }
    }

    fn update_byte(&mut self, b: u8) {
        self.buf[self.off] = b;
        self.off += 1;
        if self.off == 32 {
            let block = self.buf;
            self.sum_bytes(&block);
            self.process_block(&block);
            self.off = 0;
        }
        self.count += 1;
    }

    fn p(w: &[u8; 32]) -> [u8; 32] {
        let mut k = [0u8; 32];
        for j in 0..8 {
            k[4 * j] = w[j];
            k[4 * j + 1] = w[8 + j];
            k[4 * j + 2] = w[16 + j];
            k[4 * j + 3] = w[24 + j];
        }
        k
    }

    fn a(x: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..24].copy_from_slice(&x[8..32]);
        for j in 0..8 {
            out[24 + j] = x[j] ^ x[j + 8];
        }
        out
    }

    #[allow(clippy::needless_range_loop)]
    fn fw(s: &mut [u8; 32]) {
        let mut w = [0u16; 16];
        for i in 0..16 {
            w[i] = (s[2 * i] as u16) | ((s[2 * i + 1] as u16) << 8);
        }
        let new_last = w[0] ^ w[1] ^ w[2] ^ w[3] ^ w[12] ^ w[15];
        let mut w2 = [0u16; 16];
        w2[..15].copy_from_slice(&w[1..16]);
        w2[15] = new_last;
        for i in 0..16 {
            s[2 * i] = (w2[i] & 0xff) as u8;
            s[2 * i + 1] = (w2[i] >> 8) as u8;
        }
    }

    fn encrypt_part(&self, key: &[u8; 32], s: &mut [u8; 32], part: usize) {
        let cipher = Magma::new(key, self.sbox);
        let mut block = [0u8; 8];
        block.copy_from_slice(&self.h[part * 8..part * 8 + 8]);
        let out = cipher.encrypt_block(&block);
        s[part * 8..part * 8 + 8].copy_from_slice(&out);
    }

    #[allow(clippy::needless_range_loop)]
    fn process_block(&mut self, m: &[u8; 32]) {
        let mut u = self.h;
        let mut v = *m;
        let mut s = [0u8; 32];
        let mut w = [0u8; 32];
        for j in 0..32 {
            w[j] = u[j] ^ v[j];
        }
        self.encrypt_part(&Self::p(&w), &mut s, 0);
        for i in 1..4 {
            u = Self::a(&u);
            if i == 2 {
                for j in 0..32 {
                    u[j] ^= C2[j];
                }
            }
            v = Self::a(&Self::a(&v));
            for j in 0..32 {
                w[j] = u[j] ^ v[j];
            }
            self.encrypt_part(&Self::p(&w), &mut s, i);
        }
        for _ in 0..12 {
            Self::fw(&mut s);
        }
        for j in 0..32 {
            s[j] ^= m[j];
        }
        Self::fw(&mut s);
        for j in 0..32 {
            s[j] ^= self.h[j];
        }
        for _ in 0..61 {
            Self::fw(&mut s);
        }
        self.h = s;
    }

    #[allow(clippy::needless_range_loop)]
    fn sum_bytes(&mut self, block: &[u8; 32]) {
        let mut carry = 0u16;
        for i in 0..32 {
            let t = self.sum[i] as u16 + block[i] as u16 + carry;
            self.sum[i] = (t & 0xff) as u8;
            carry = t >> 8;
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bits = self.count * 8;
        let mut l = [0u8; 32];
        l[..8].copy_from_slice(&bits.to_le_bytes());
        while self.off != 0 {
            self.update_byte(0);
        }
        self.process_block(&l);
        let sum = self.sum;
        self.process_block(&sum);
        self.h
    }
}

/// One-shot digest with the D-A S-box.
pub fn gost94(data: &[u8]) -> [u8; 32] {
    let mut d = Gost94::new();
    d.update(data);
    d.finalize()
}
