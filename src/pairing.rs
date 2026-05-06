//! ペアリングコード (SAS: Short Authentication String) の計算と表示
//!
//! 接続確立後、双方が 16 バイトの揮発的 nonce を交換し、両者の EndpointId・
//! ALPN・両 nonce から BLAKE3 で 20 ビットの値を導出する。値は XXX-XXXX
//! 形式に整形され、利用者は別経路 (通話・対面など) で同一性を確認する。
//!
//! 攻撃者がチケットを差し替えて MitM を仕掛けた場合、攻撃者は別の Endpoint
//! 鍵を持つため、両者に表示される SAS が一致しない。
//!
//! 詳細は ADR-0004 を参照。

use blake3::Hasher;
use rand::RngCore;
use zeroize::Zeroizing;

/// nonce の長さ (バイト)
pub const NONCE_LEN: usize = 16;

/// SAS の有効ビット数
/// 20 ビット = 約 100 万通り。一回限りの確認用としては実用的下限。
pub const SAS_BITS: u32 = 20;

/// 揮発的な nonce を生成する
///
/// 戻り値は `Zeroizing` で包まれており、Drop 時にメモリがゼロ化される。
pub fn generate_nonce() -> Zeroizing<[u8; NONCE_LEN]> {
    let mut nonce = Zeroizing::new([0u8; NONCE_LEN]);
    rand::rngs::OsRng.fill_bytes(&mut *nonce);
    nonce
}

/// SAS を計算する
///
/// 双方の EndpointId は辞書順にソートして結合することで、listen 側と
/// connect 側が同一の値を独立に計算できる。同様に nonce も EndpointId の
/// 順に対応させる。
pub fn compute_sas(
    local_id: &[u8],
    remote_id: &[u8],
    alpn: &[u8],
    local_nonce: &[u8],
    remote_nonce: &[u8],
) -> u32 {
    let (id_a, id_b, nonce_a, nonce_b) = if local_id <= remote_id {
        (local_id, remote_id, local_nonce, remote_nonce)
    } else {
        (remote_id, local_id, remote_nonce, local_nonce)
    };

    let mut hasher = Hasher::new();
    // ドメインセパレータ。プロトコル進化時はこの文字列を更新する。
    hasher.update(b"bluewren-sas-v1\0");
    // 各フィールドに長さプレフィクスを付けて concatenation 攻撃を防ぐ
    write_field(&mut hasher, id_a);
    write_field(&mut hasher, id_b);
    write_field(&mut hasher, alpn);
    write_field(&mut hasher, nonce_a);
    write_field(&mut hasher, nonce_b);

    let hash = hasher.finalize();
    let bytes = hash.as_bytes();

    // 上位 24 ビットを読み取り、20 ビットに切り詰める
    let raw =
        ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32);
    raw >> (24 - SAS_BITS)
}

fn write_field(hasher: &mut Hasher, field: &[u8]) {
    hasher.update(&(field.len() as u32).to_be_bytes());
    hasher.update(field);
}

/// SAS を XXX-XXXX 形式に整形する (利用者表示用)
pub fn format_sas(value: u32) -> String {
    // 20 ビット = 最大 1,048,575 (7 桁)
    // 視覚的に区切るため XXX-XXXX 形式に整形する
    format!("{:03}-{:04}", value / 10_000, value % 10_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_generation_produces_unique_values() {
        let n1 = generate_nonce();
        let n2 = generate_nonce();
        // 16 バイトすべてがゼロ確率は事実上ゼロ
        assert_ne!(*n1, *n2);
        assert_ne!(*n1, [0u8; NONCE_LEN]);
    }

    #[test]
    fn sas_is_symmetric() {
        // listen 側と connect 側で local/remote が入れ替わっても同じ SAS になる
        let id_a = [1u8; 32];
        let id_b = [2u8; 32];
        let nonce_a = [10u8; NONCE_LEN];
        let nonce_b = [20u8; NONCE_LEN];
        let alpn = b"/bluewren/0.2";

        let sas_from_a = compute_sas(&id_a, &id_b, alpn, &nonce_a, &nonce_b);
        let sas_from_b = compute_sas(&id_b, &id_a, alpn, &nonce_b, &nonce_a);
        assert_eq!(sas_from_a, sas_from_b);
    }

    #[test]
    fn sas_differs_for_different_peers() {
        // 異なる相手 ID では異なる SAS になる (MitM 検出の核心)
        let id_a = [1u8; 32];
        let id_b = [2u8; 32];
        let id_c = [3u8; 32]; // 攻撃者の ID
        let nonce_a = [10u8; NONCE_LEN];
        let nonce_b = [20u8; NONCE_LEN];
        let alpn = b"/bluewren/0.2";

        let legit = compute_sas(&id_a, &id_b, alpn, &nonce_a, &nonce_b);
        let mitm = compute_sas(&id_a, &id_c, alpn, &nonce_a, &nonce_b);
        assert_ne!(legit, mitm);
    }

    #[test]
    fn sas_uses_nonces_for_replay_resistance() {
        let id_a = [1u8; 32];
        let id_b = [2u8; 32];
        let nonce_a1 = [10u8; NONCE_LEN];
        let nonce_a2 = [11u8; NONCE_LEN];
        let nonce_b = [20u8; NONCE_LEN];
        let alpn = b"/bluewren/0.2";

        let sas1 = compute_sas(&id_a, &id_b, alpn, &nonce_a1, &nonce_b);
        let sas2 = compute_sas(&id_a, &id_b, alpn, &nonce_a2, &nonce_b);
        assert_ne!(sas1, sas2);
    }

    #[test]
    fn sas_is_within_bit_range() {
        // 計算結果が 20 ビット範囲に収まっていること
        for i in 0..100u32 {
            let id_a = [(i & 0xFF) as u8; 32];
            let id_b = [((i + 1) & 0xFF) as u8; 32];
            let nonce_a = [(i + 2) as u8; NONCE_LEN];
            let nonce_b = [(i + 3) as u8; NONCE_LEN];
            let sas = compute_sas(&id_a, &id_b, b"/test", &nonce_a, &nonce_b);
            assert!(sas < (1 << SAS_BITS));
        }
    }

    #[test]
    fn format_sas_produces_seven_digits() {
        assert_eq!(format_sas(0), "000-0000");
        assert_eq!(format_sas(1_048_575), "104-8575");
        // 1_234_567 % 2^20 = 185_991 → "018-5991"
        assert_eq!(format_sas(123_4567 % (1 << SAS_BITS)), "018-5991");
    }

    #[test]
    fn concatenation_attack_resistance() {
        // 異なるフィールド組合せが同じハッシュを生まない (長さプレフィクスの効果)
        let alpn = b"/bluewren/0.2";

        // ケース1: id="ab", nonce="cd"
        let sas1 = compute_sas(b"ab", b"xy", alpn, b"cd", b"ef");
        // ケース2: id="abc", nonce="d" (concatenation 後は同じバイト列)
        let sas2 = compute_sas(b"abc", b"xy", alpn, b"d", b"ef");
        // 長さプレフィクスがあれば異なる値になる
        assert_ne!(sas1, sas2);
    }
}
