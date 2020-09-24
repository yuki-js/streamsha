use hex_literal::hex;
use streamsha::traits::{Resumable, StreamHasher};
use streamsha::*;

const vectors: &[(&[u8], &[u8])] = &[
    (&[], &hex!("cf83e1357eefb8bd f1542850d66d8007 d620e4050b5715dc 83f4a921d36ce9ce 47d0d13c5d85f2b0 ff8318d2877eec2f 63b931bd47417a81 a538327af927da3e")),
    (&[0; 111], &hex!("77ddd3a542e530fd 047b8977c657ba6c e72f1492e360b2b2 212cd264e75ec038 82e4ff0525517ab4 207d14c70c2259ba 88d4d335ee0e7e20 543d22102ab1788c")),
    (&[0; 112], &hex!("2be2e788c8a8adea a9c89a7f78904cac ea6e39297d75e057 3a73c756234534d6 627ab4156b48a665 7b29ab8beb733340 40ad39ead81446bb 09c70704ec707952")),
    (&[0; 113], &hex!("0e67910bcf0f9ccd e5464c63b9c850a1 2a759227d16b040d 98986d54253f9f34 322318e56b8feb86 c5fb2270ed87f312 52f7f68493ee7597 43909bd75e4bb544")),
    (&[0; 122], &hex!("4f3f095d015be4a7 a7cc0b8c04da4aa0 9e74351e3a97651f 744c23716ebd9b3e 822e5077a01baa5c c0ed45b9249e88ab 343d4333539df21e d229da6f4a514e0f")),
    (&[0; 1000], &hex!("ca3dff61bb23477a a6087b27508264a6 f9126ee3a004f53c b8db942ed345f2f2 d229b4b59c859220 a1cf1913f34248e3 803bab650e849a3d 9a709edc09ae4a76")),
    (&[0x41; 1000], &hex!("329c52ac62d1fe73 1151f2b895a00475 445ef74f50b979c6 f7bb7cae349328c1 d4cb4f7261a0ab43 f936a24b000651d4 a824fcdd577f211a ef8f806b16afe8af")),
    (&[0x55; 1005], &hex!("59f5e54fe299c6a8 764c6b199e44924a 37f59e2b56c3ebad 939b7289210dc8e4 c21b9720165b0f4d 4374c90f1bf4fb4a 5ace17a116179801 5052893a48c3d161")),
];

#[test]
fn it_can_hash_vectors() {
    for i in vectors.iter() {
        let mut hasher = Sha512::new();
        hasher.update(i.0);
        let hash = hasher.finish();
        assert_eq!(&hash[..], i.1)
    }
}
#[test]
fn it_can_hash_0x20000000_z() {
    let mut hasher = Sha512::new();
    for _ in 0..0x100000 {
        hasher.update(&[0x5a; 0x200]);
    }
    let hash = hasher.finish();
    assert_eq!(&hash[..], &hex!("da172279f3ebbda9 5f6b6e1e5f0ebec6 82c25d3d93561a16 24c2fa9009d64c7e 9923f3b46bcaf11d 39a531f43297992b a4155c7e827bd0f1 e194ae7ed6de4cac")[..])
}

#[test]
fn it_can_hash_0x41000000_zeros() {
    let mut hasher = Sha512::new();
    for _ in 0..0x100000 {
        hasher.update(&[0; 0x410]);
    }
    let hash = hasher.finish();
    assert_eq!(&hash[..], &hex!("14b1be901cb43549 b4d831e61e5f9df1 c791c85b50e85f9d 6bc64135804ad43c e8402750edbe4e5c 0fc170b99cf78b9f 4ecb9c7e02a15791 1d1bd1832d76784f")[..])
}
#[test]
fn it_can_hash_0x6000003e_b() {
    let mut hasher = Sha512::new();
    for _ in 0..0x100000 {
        hasher.update(&[0x42; 0x600]);
    }
    hasher.update(&[0x42; 0x3e]);
    let hash = hasher.finish();
    assert_eq!(&hash[..], &hex!("fd05e13eb771f051 90bd97d62647157e a8f1f6949a52bb6d aaedbad5f578ec59 b1b8d6c4a7ecb2fe ca6892b4dc138771 670a0f3bd577eea3 26aed40ab7dd58b1")[..])
}
