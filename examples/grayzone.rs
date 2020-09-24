use hex_literal::hex;
use streamsha::hash_state::{HashState, Sha256HashState};
use streamsha::traits::{Resumable, StreamHasher};
use streamsha::{Sha1, Sha256};
extern crate hex_slice;
#[macro_use]
extern crate lazy_static;

lazy_static! {
    // 利用者証明用電子証明書の全文
    static ref AUTH_CERT: &'static [u8] = &hex!("3082062130820509a0030201020204012d57ca300d06092a864886f70d01010b0500308182310b3009060355040613024a50310d300b060355040a0c044a504b4931253023060355040b0c1c4a504b4920666f7220757365722061757468656e7469636174696f6e313d303b060355040b0c344a6170616e204167656e637920666f72204c6f63616c20417574686f7269747920496e666f726d6174696f6e2053797374656d73301e170d3139303732353135323830365a170d3234303530323134353935395a302f310b3009060355040613024a503120301e06035504030c17383430343434453337504146484e30383232303030334130820122300d06092a864886f70d01010105000382010f003082010a0282010100c2e48c45c07363e246be44407c8af5317cbccd3aa8be5d26129224525ac9fd73bc65296102d48744600952f0493c397657c966e2564ff9ef5175357eec9628036096326107a90bd538f67390aaecbcd85672bdc66f088b3f1fa0657009c146dbec38111c50757358e3016803cf5ece665927b377afdf058432a624b372d2e39cf534ab9ed449da12ba239fe0dd96f65c72ccea6b6bfd9733c41e90edee1f842078ac5cde7c95c6242a322516ef22927f35abb8afe8327633d7ded0959384d205853b84726fabed29182f0213b6a74f118651d2c4c415b8253d3ac2d339c8775361b6201849fe99626f591f558c5c916a79182c856bb1599ad12be5d33748e7990203010001a38202ef308202eb300e0603551d0f0101ff04040302078030130603551d25040c300a06082b0601050507030230490603551d200101ff043f303d303b060b2a83088c9b55080501031e302c302a06082b06010505070201161e687474703a2f2f7777772e6a706b692e676f2e6a702f6370732e68746d6c3081b70603551d120481af3081aca481a93081a6310b3009060355040613024a5031273025060355040a0c1ee585ace79a84e5808be4babae8aa8de8a8bce382b5e383bce38393e382b931393037060355040b0c30e585ace79a84e5808be4babae8aa8de8a8bce382b5e383bce38393e382b9e588a9e794a8e88085e8a8bce6988ee794a831333031060355040b0c2ae59cb0e696b9e585ace585b1e59ba3e4bd93e68385e5a0b1e382b7e382b9e38386e383a0e6a99fe6a78b3081b10603551d1f0481a93081a63081a3a081a0a0819da4819a308197310b3009060355040613024a50310d300b060355040a0c044a504b4931253023060355040b0c1c4a504b4920666f7220757365722061757468656e7469636174696f6e3120301e060355040b0c1743524c20446973747269627574696f6e20506f696e747331143012060355040b0c0b49626172616b692d6b656e311a301806035504030c115473756b7562612d7368692043524c4450303a06082b06010505070101042e302c302a06082b06010505073001861e687474703a2f2f6f637370617574686e6f726d2e6a706b692e676f2e6a703081af0603551d230481a73081a480149567951b5ca70d84a0fff1d85a87f1aab1340385a18188a48185308182310b3009060355040613024a50310d300b060355040a0c044a504b4931253023060355040b0c1c4a504b4920666f7220757365722061757468656e7469636174696f6e313d303b060355040b0c344a6170616e204167656e637920666f72204c6f63616c20417574686f7269747920496e666f726d6174696f6e2053797374656d73820101301d0603551d0e0416041477f6c4d716d8cde22a27eed3d3af496e1fb0eff5300d06092a864886f70d01010b050003820101002addf5bce542900c6f93ab3ccfce694bc20fbf94d6096342c217cff14658047f4c1e40db2368267842081093b80a8a1cb9d0925efe110240a7115fb9831ecbb5f70e1fa38bb97842ad68204f411a938ac7fb316bb86dd0e32ea248d780bf8bf4e130dbf156a336ede2c0a1a52f4c46f25c59843973c19e910a11a72b802a55fe4a98d202003f287ab62f90bbf83f577c74a499561ee005ad9bed1056977a529a4f3c8cd395a37e7f5b3c9e7f98c113a091ab75525589e91dc5f152d35ad209f6c066c0b69bc1193b92c6eb8781d5cccbc353f6d521cc37af3cac600c61df67a7117c8dfc5b33446276e2cc0515e859bea1dfd37aa4c238e665f655d1b14f5fd3");

    // シリアル番号を表すバイト列を抜き出した(13バイトめから18バイトめまで)
    static ref SERIAL_NUMBER: &'static [u8] = &AUTH_CERT[13..=18];

    // 公開鍵より前の部分を抜き出したもの。シリアル番号を含む。(先頭から271バイトめまで)
    static ref BEFORE_PUBKEY: &'static [u8] = &AUTH_CERT[0..=271];

    // 公開鍵を抜き出したもの。証明書にカプセル化されて記録されているDERエンコード済み公開鍵。(272バイトめから541バイトめまで)
    static ref PUBKEY: &'static [u8] = &AUTH_CERT[272..=541];

    // 公開鍵より後の部分を抜き出したもの。(542バイトめから末尾まで)
    static ref AFTER_PUBKEY: &'static [u8] = &AUTH_CERT[542..];

    // SubjectKeyIdentifierフィールド。これは公開鍵のSHA-1ハッシュ値と等しい。これを用いて公開鍵の真正性を検証することもできる。(1277バイトめから1296バイトめまで)
    static ref SUBJ_KEY_ID: &'static [u8] = &AUTH_CERT[1277..=1296];

}

/// 電子証明書の全文をハッシュ化する
fn calculate_original_hash() -> [u8; 32] {
    // ハッシュに必要な構造体を生成
    let mut hasher = Sha256::new();

    // 入力し、ハッシュ計算
    hasher.update(&AUTH_CERT);

    // 最終ブロックを計算し、ハッシュ処理を完了させ、ハッシュ値を返す
    let hash = hasher.finish();
    hash
}

/// クライアントが処理すべき部分を想定している。シリアル番号を含んだデータを読んでから中断してハッシュステートを返す。入力サイズ(バイト)が64で割り切れない場合、余りの入力データがハッシュステートに含まれる。
fn calculate_client_hash() -> HashState {
    // ハッシュに必要な構造体を生成
    let mut hasher = Sha256::new();

    // 電子証明書の一部を入力し、ハッシュ計算
    hasher.update(&BEFORE_PUBKEY);

    let state = hasher.pause();
    state
}

/// ノード運用者が処理する部分を想定している。ハッシュステートを受け取って、処理を再開する。
fn calculate_server_hash(state: HashState) -> [u8; 32] {
    // 中断した時のハッシュステートを復元する
    let mut resumed = Sha256::resume(state).expect("復元失敗！");

    // 公開鍵をハッシュする
    resumed.update(&PUBKEY);

    // 公開鍵より後の部分をハッシュする
    resumed.update(&AFTER_PUBKEY);

    // 最終ブロックを計算し、ハッシュ処理を完了させ、ハッシュ値を返す
    let hash = resumed.finish();
    hash
}

/// 公開鍵のSHA-1ハッシュを求める
fn calculate_pubkey_sha1() -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(&PUBKEY);
    let hash = hasher.finish();
    hash
}

fn main() {
    let original = calculate_original_hash();
    println!("全文のハッシュ値: {:x?}", original);
    let client_hashstate = calculate_client_hash();
    if let HashState::Sha256(client_state) = &client_hashstate {
        println!("出力されたハッシュステート: {{");
        println!("\tHの値: {:x?}", client_state.h);
        println!("\t入力の合計サイズ: {}", client_state.message_len);
        println!(
            "\t余りのデータ: {:x?}",
            &client_state.current_block[..client_state.block_len]
        );
        println!("}}");
    } else {
        panic!("SHA-256ステートではありません。失敗です。");
    }
    let server_hash = calculate_server_hash(client_hashstate);
    println!("ノード運用者が計算したハッシュ: {:x?}", original);
    if original == server_hash {
        println!("ハッシュ値が一致しました。成功です。");
    } else {
        println!("ハッシュ値が一致しません。失敗です。");
    }

    println!("--------");
    let pubkeyhash = calculate_pubkey_sha1();
    println!("公開鍵SHA-1ハッシュ: {:x?}", pubkeyhash);
    if &pubkeyhash[..] == &SUBJ_KEY_ID[..] {
        println!("公開鍵ハッシュが一致しました。成功です。");
    } else {
        println!("公開鍵ハッシュが一致しません。失敗です。");
    }
}
