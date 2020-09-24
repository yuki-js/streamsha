use crate::arith::rotl;
use crate::consts::*;
use crate::hash_state;
use crate::hash_state::HashState;
use crate::traits::*;
/// Calculates SHA-1
pub struct Sha1 {
    /// Hash values
    h: [u32; 5],
    /// The max length of message (in bytes) defined in fips 180-4
    message_len: u64,
    /// The length of `current_block` in bytes
    block_len: usize,
    /// The incomplete block that is waiting to be filled and hashed
    current_block: [u8; SHA1_BLOCK_SIZE],
}

impl Sha1 {
    /// Create new instance
    pub const fn new() -> Self {
        Self {
            h: SHA1_H,
            current_block: [0u8; SHA1_BLOCK_SIZE],
            block_len: 0usize,
            message_len: 0u64,
        }
    }
    /// Compute hash for current block
    fn process_block(&mut self) {
        if self.block_len != SHA1_BLOCK_SIZE {
            panic!("block is not filled");
        }
        let mut w = [0 as u32; 80];
        for t in 0..16 {
            w[t] = self.get_word32_in_block(t);
        }
        for t in 16..80 {
            w[t] = rotl(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
        }

        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        for t in 0..80 {
            let t1 = rotl(a, 5) + Self::ft(t, b, c, d) + e + SHA1_K(t) + w[t];
            e = d;
            d = c;
            c = rotl(b, 30);
            b = a;
            a = t1;
        }
        self.h[0] = a + self.h[0];
        self.h[1] = b + self.h[1];
        self.h[2] = c + self.h[2];
        self.h[3] = d + self.h[3];
        self.h[4] = e + self.h[4];

        self.current_block = [0u8; SHA1_BLOCK_SIZE]; // next block
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

/// SHA1 functions
impl Sha1 {
    fn ft(t: usize, x: u32, y: u32, z: u32) -> u32 {
        match t {
            0..=19 => Self::ch(x, y, z),
            20..=39 => Self::parity(x, y, z),
            40..=59 => Self::maj(x, y, z),
            60..=79 => Self::parity(x, y, z),
            _ => panic!("t is out of range"),
        }
    }
    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }
    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }
    fn parity(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }
}
impl StreamHasher for Sha1 {
    type Output = [u8; 20];
    const BLOCK_SIZE: usize = SHA1_BLOCK_SIZE;
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
        for i in 0..5 {
            let word_area = &mut final_hash[i * 4..i * 4 + 4];
            word_area.clone_from_slice(&self.h[i].to_be_bytes());
        }
        return final_hash;
    }
}
impl Resumable for Sha1 {
    fn pause(self) -> HashState {
        let h: [u32; 5] = [self.h[0], self.h[1], self.h[2], self.h[3], self.h[4]];
        HashState::Sha1(hash_state::Sha1HashState {
            h,
            message_len: self.message_len,
            block_len: self.block_len,
            current_block: self.current_block,
        })
    }
    fn resume(hash_state: HashState) -> Result<Self, hash_state::Error> {
        match hash_state {
            HashState::Sha1(hs) => Ok(Self {
                h: [hs.h[0], hs.h[1], hs.h[2], hs.h[3], hs.h[4]],
                message_len: hs.message_len,
                block_len: hs.block_len,
                current_block: hs.current_block,
            }),
            _ => Err(hash_state::Error::HashTypeNotMatch),
        }
    }
}
impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}
