//! Hash state enum / state structs for each hash algorithms
use crate::consts::*;
pub enum HashState {
    Sha1(Sha1HashState),
    Sha256(Sha256HashState),
    Sha512(Sha512HashState),
}
pub struct Sha1HashState {
    pub h: [u32; 5],
    pub message_len: u64,
    pub block_len: usize,
    pub current_block: [u8; SHA1_BLOCK_SIZE],
}
pub struct Sha256HashState {
    pub h: [u32; 8],
    pub message_len: u64,
    pub block_len: usize,
    pub current_block: [u8; SHA256_BLOCK_SIZE],
}
pub struct Sha512HashState {
    pub h: [u64; 8],
    pub message_len: u128,
    pub block_len: usize,
    pub current_block: [u8; SHA512_BLOCK_SIZE],
}
#[derive(Debug)]
pub enum Error {
    HashTypeNotMatch,
}
