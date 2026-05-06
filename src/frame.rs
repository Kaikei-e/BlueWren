//! 固定長フレーム v1 のエンコード／デコード
//!
//! 構造:
//!   [version: 1B][type: 1B][len: 2B][payload: N bytes][padding: random]
//!   合計 FRAME_SIZE バイト
//!
//! 詳細は ADR-0003 を参照。

use anyhow::{bail, Result};
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 1 フレームの固定長 (バイト)
pub const FRAME_SIZE: usize = 256;

/// ヘッダ長 (version 1B + type 1B + len 2B)
pub const HEADER_SIZE: usize = 4;

/// 1 メッセージあたりの最大ペイロード長 (バイト)
pub const MAX_PAYLOAD: usize = FRAME_SIZE - HEADER_SIZE;

/// プロトコルバージョン
pub const PROTOCOL_VERSION: u8 = 0x01;

/// フレーム種別
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// 通常のチャットメッセージ
    Message = 0x01,
    /// keepalive / 将来の cover traffic 予約
    Dummy = 0x02,
    /// セッション終了などの制御信号
    Control = 0x03,
    /// SAS 用の nonce 交換
    SasHandshake = 0x04,
}

impl FrameType {
    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0x01 => Ok(FrameType::Message),
            0x02 => Ok(FrameType::Dummy),
            0x03 => Ok(FrameType::Control),
            0x04 => Ok(FrameType::SasHandshake),
            x => bail!("不明なフレーム型: 0x{:02x}", x),
        }
    }
}

/// 受信フレーム
pub struct Frame {
    pub frame_type: FrameType,
    pub payload: Vec<u8>,
}

/// フレームを書き込む
pub async fn write_frame<W: AsyncWriteExt + Unpin>(
    stream: &mut W,
    frame_type: FrameType,
    payload: &[u8],
) -> Result<()> {
    if payload.len() > MAX_PAYLOAD {
        bail!(
            "ペイロードが上限超過 (最大 {} バイト, 実際 {} バイト)",
            MAX_PAYLOAD,
            payload.len()
        );
    }

    let mut frame = [0u8; FRAME_SIZE];
    frame[0] = PROTOCOL_VERSION;
    frame[1] = frame_type as u8;
    let len = payload.len() as u16;
    frame[2..4].copy_from_slice(&len.to_be_bytes());
    frame[HEADER_SIZE..HEADER_SIZE + payload.len()].copy_from_slice(payload);

    // パディング部分にランダムバイトを充填
    // ゼロ埋めではなく乱数にする理由: QUIC が暗号化するため外部からは
    // 判別不能だが、暗号スキームへの保険として予測不能な値を入れる
    let mut rng = rand::rngs::OsRng;
    rng.fill_bytes(&mut frame[HEADER_SIZE + payload.len()..]);

    stream.write_all(&frame).await?;
    Ok(())
}

/// フレームを 1 つ読み取る
pub async fn read_frame<R: AsyncReadExt + Unpin>(stream: &mut R) -> Result<Option<Frame>> {
    let mut frame = [0u8; FRAME_SIZE];
    match stream.read_exact(&mut frame).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }

    if frame[0] != PROTOCOL_VERSION {
        bail!(
            "プロトコルバージョン不一致 (期待 0x{:02x}, 実際 0x{:02x})",
            PROTOCOL_VERSION,
            frame[0]
        );
    }

    let frame_type = FrameType::from_byte(frame[1])?;
    let len = u16::from_be_bytes([frame[2], frame[3]]) as usize;
    if len > MAX_PAYLOAD {
        bail!("不正なフレーム: 長さフィールド超過 ({})", len);
    }

    Ok(Some(Frame {
        frame_type,
        payload: frame[HEADER_SIZE..HEADER_SIZE + len].to_vec(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn roundtrip_message_frame() {
        let (mut a, mut b) = duplex(1024);
        write_frame(&mut a, FrameType::Message, b"hello")
            .await
            .unwrap();
        let frame = read_frame(&mut b).await.unwrap().unwrap();
        assert_eq!(frame.frame_type, FrameType::Message);
        assert_eq!(frame.payload, b"hello");
    }

    #[tokio::test]
    async fn roundtrip_sas_handshake_frame() {
        let (mut a, mut b) = duplex(1024);
        let nonce = [42u8; 16];
        write_frame(&mut a, FrameType::SasHandshake, &nonce)
            .await
            .unwrap();
        let frame = read_frame(&mut b).await.unwrap().unwrap();
        assert_eq!(frame.frame_type, FrameType::SasHandshake);
        assert_eq!(frame.payload, nonce);
    }

    #[tokio::test]
    async fn roundtrip_max_size_message() {
        let (mut a, mut b) = duplex(1024);
        let payload = vec![0xAB; MAX_PAYLOAD];
        write_frame(&mut a, FrameType::Message, &payload)
            .await
            .unwrap();
        let frame = read_frame(&mut b).await.unwrap().unwrap();
        assert_eq!(frame.payload, payload);
    }

    #[tokio::test]
    async fn rejects_oversized_payload() {
        let (mut a, _b) = duplex(1024);
        let payload = vec![0xAB; MAX_PAYLOAD + 1];
        assert!(write_frame(&mut a, FrameType::Message, &payload)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn rejects_unknown_frame_type() {
        // 不正なフレーム型 0xFF を含むバイト列を直接送る
        let (mut a, mut b) = duplex(FRAME_SIZE);
        let mut frame = [0u8; FRAME_SIZE];
        frame[0] = PROTOCOL_VERSION;
        frame[1] = 0xFF; // 不正な type
        a.write_all(&frame).await.unwrap();
        let result = read_frame(&mut b).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rejects_wrong_version() {
        let (mut a, mut b) = duplex(FRAME_SIZE);
        let mut frame = [0u8; FRAME_SIZE];
        frame[0] = 0xFF; // 不正な version
        frame[1] = FrameType::Message as u8;
        a.write_all(&frame).await.unwrap();
        let result = read_frame(&mut b).await;
        assert!(result.is_err());
    }
}
