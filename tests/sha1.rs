use hex_literal::hex;
use streamsha::traits::{Resumable, StreamHasher};
use streamsha::*;

const vectors: &[(&[u8], [u8; 20])] = &[
    (b"abc", hex!("A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D")),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        hex!("84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1"),
    ),
];
#[test]
fn it_can_hash_vectors() {
    for i in vectors.iter() {
        let mut hasher = Sha1::new();
        hasher.update(i.0);
        let hash = hasher.finish();
        assert_eq!(hash, i.1)
    }
}
