use crate::arith::rotr;
use crate::consts::*;
use crate::hash_state;
use crate::hash_state::HashState;
use crate::traits::*;
/// Calculates SHA-256
pub struct Sha256 {
    /// Hash values
    h: [u32; 8],
    /// The max length of message (in bytes) defined in fips 180-4
    message_len: u64,
    /// The length of `current_block` in bytes
    block_len: usize,
    /// The incomplete block that is waiting to be filled and hashed
    current_block: [u8; SHA256_BLOCK_SIZE],
}

impl Sha256 {
    /// Create new instance
    pub const fn new() -> Self {
        Self {
            h: SHA256_H,
            current_block: [0u8; SHA256_BLOCK_SIZE],
            block_len: 0usize,
            message_len: 0u64,
        }
    }
    /// Compute hash for current block
    fn process_block(&mut self) {
        if self.block_len != SHA256_BLOCK_SIZE {
            panic!("block is not filled");
        }
        let mut w = [0 as u32; 64];
        for t in 0..16 {
            w[t] = self.get_word32_in_block(t)
        }
        for t in 16..64 {
            w[t] = Self::lsigma1(w[t - 2]) + w[t - 7] + Self::lsigma0(w[t - 15]) + w[t - 16];
        }
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];

        for t in 0..64 {
            let t1 = h + Self::sigma1(e) + Self::ch(e, f, g) + SHA256_K[t] + w[t];
            let t2 = Self::sigma0(a) + Self::maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        self.h[0] = a + self.h[0];
        self.h[1] = b + self.h[1];
        self.h[2] = c + self.h[2];
        self.h[3] = d + self.h[3];
        self.h[4] = e + self.h[4];
        self.h[5] = f + self.h[5];
        self.h[6] = g + self.h[6];
        self.h[7] = h + self.h[7];

        self.current_block = [0u8; SHA256_BLOCK_SIZE]; // next block
        self.block_len = 0; // reset block
    }

    /// Conbines 4 byte and returns as u32.
    const fn get_word32_in_block(&self, i: usize) -> u32 {
        ((self.current_block[i * 4] as u32) << 24)
            + ((self.current_block[i * 4 + 1] as u32) << 16)
            + ((self.current_block[i * 4 + 2] as u32) << 8)
            + (self.current_block[i * 4 + 3] as u32)
    }
}

/// SHA256 functions
impl Sha256 {
    fn sigma0(x: u32) -> u32 {
        rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
    }
    fn sigma1(x: u32) -> u32 {
        rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
    }
    fn lsigma0(x: u32) -> u32 {
        rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
    }
    fn lsigma1(x: u32) -> u32 {
        rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
    }
    const fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }
    const fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }
}
impl StreamHasher for Sha256 {
    type Output = [u8; 32];
    const BLOCK_SIZE: usize = SHA256_BLOCK_SIZE;
    fn update(&mut self, buf: &[u8]) -> usize {
        let len = buf.len();
        if len == 0 {
            // if no data or no remaining data, stop
            return 0;
        }
        let writable_len = Self::BLOCK_SIZE - self.block_len;
        let writable_area = &mut self.current_block[self.block_len..];

        if len >= writable_len {
            // overflows block or buf.len() == writable_len
            writable_area.clone_from_slice(&buf[0..writable_len]); // fill block
            self.block_len += writable_len;
            self.message_len += writable_len as u64;
            self.process_block(); // perform hash calculation
            self.update(&buf[writable_len..]); // recursively write remaining
        } else {
            // don't fill block
            let write_area = &mut self.current_block[self.block_len..self.block_len + len];
            write_area.clone_from_slice(&buf[..]);
            self.block_len += len;
            self.message_len += len as u64;
        }
        len
    }
    fn finish(mut self) -> Self::Output {
        self.current_block[self.block_len] = 0x80;
        if self.block_len + 1 + 8 > Self::BLOCK_SIZE {
            // data||0x80||size(u64) overflows block
            self.block_len = Self::BLOCK_SIZE;
            self.process_block(); // perform hash calculation
        }
        let writable_area = &mut self.current_block[Self::BLOCK_SIZE - 8..Self::BLOCK_SIZE];
        let len_bits = self.message_len * 8;
        writable_area.clone_from_slice(&len_bits.to_be_bytes());
        self.block_len = Self::BLOCK_SIZE;
        self.process_block();
        let mut final_hash: Self::Output = Default::default();
        for i in 0..8 {
            let word_area = &mut final_hash[i * 4..i * 4 + 4];
            word_area.clone_from_slice(&self.h[i].to_be_bytes());
        }
        return final_hash;
    }
}
impl Resumable for Sha256 {
    fn pause(self) -> HashState {
        let h: [u32; 8] = [
            self.h[0], self.h[1], self.h[2], self.h[3], self.h[4], self.h[5], self.h[6], self.h[7],
        ];
        HashState::Sha256(hash_state::Sha256HashState {
            h,
            message_len: self.message_len,
            block_len: self.block_len,
            current_block: self.current_block,
        })
    }
    fn resume(hash_state: HashState) -> Result<Self, hash_state::Error> {
        match hash_state {
            HashState::Sha256(hs) => Ok(Self {
                h: [
                    hs.h[0], hs.h[1], hs.h[2], hs.h[3], hs.h[4], hs.h[5], hs.h[6], hs.h[7],
                ],
                message_len: hs.message_len,
                block_len: hs.block_len,
                current_block: hs.current_block,
            }),
            _ => Err(hash_state::Error::HashTypeNotMatch),
        }
    }
}
impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}
