//! セッション管理
//!
//! Iroh エンドポイントの構築、listen / connect の実装、SAS ハンドシェイク、
//! チャットループを提供する。
//!
//! Iroh 0.97 系の API を使用 (NodeId→EndpointId, NodeAddr→EndpointAddr,
//! iroh-tickets が独立クレート化)。

use crate::cli::ConnectOpts;
use crate::frame::{read_frame, write_frame, FrameType, MAX_PAYLOAD};
use crate::pairing::{compute_sas, format_sas, generate_nonce, NONCE_LEN};
use crate::sanitize::sanitize_for_terminal;
use anyhow::{bail, Context, Result};
use iroh::endpoint::{presets, Builder as EndpointBuilder, Connection};
use iroh::Endpoint;
use iroh_tickets::endpoint::EndpointTicket;
use std::io::Write;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::time::timeout;
use tracing::warn;
use zeroize::Zeroizing;

/// アプリケーションプロトコル識別子 (ALPN)
pub const ALPN: &[u8] = b"/bluewren/0.2";

// タイムアウト定数 (監査 F-08 対応)
const READ_FRAME_TIMEOUT: Duration = Duration::from_secs(30);
const SAS_CONFIRM_TIMEOUT: Duration = Duration::from_secs(120);
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const SESSION_MAX_DURATION: Duration = Duration::from_secs(3600);

/// ADR-0002: Builder + ALPN 先行設定。
///
/// 短縮形 `Endpoint::bind().await` は使用しない。受け入れ ALPN を構築時の
/// 不変属性として明示するため、`presets::N0` と `alpns(..)` を bind 前に
/// 確定させる。テストからは bind 前段階を共有できる。
fn endpoint_builder() -> EndpointBuilder {
    Endpoint::builder(presets::N0).alpns(vec![ALPN.to_vec()])
}

/// 揮発的鍵で Iroh エンドポイントを構築する共通処理
///
/// プロセス起動毎に Iroh が新規 Ed25519 鍵を内部生成する。鍵バイト列は
/// アプリ層には露出しない (ADR-0002)。
async fn build_endpoint() -> Result<Endpoint> {
    let endpoint = endpoint_builder()
        .bind()
        .await
        .context("Iroh エンドポイントのバインドに失敗")?;
    // online() でリレー登録完了を待つ。これにより addr() が完全な情報を返す。
    endpoint.online().await;
    Ok(endpoint)
}

/// Listen モード: チケットを表示し、最初の接続を受け入れる
pub async fn run_listen() -> Result<()> {
    let endpoint = build_endpoint().await?;

    // EndpointAddr (Iroh 0.97 系では旧 NodeAddr)
    let addr = endpoint.addr();
    let ticket = EndpointTicket::new(addr);

    println!();
    println!("══════════════════════════════════════════════════════════════");
    println!("  以下のチケットを安全な経路 (対面・暗号化済みチャット等)");
    println!("  で相手に共有してください。");
    println!("══════════════════════════════════════════════════════════════");
    println!();
    println!("  {}", ticket);
    println!();
    println!("══════════════════════════════════════════════════════════════");
    println!("  接続を待機しています... (Ctrl+C で終了)");
    println!();

    // 1対1 専用なので最初の接続のみ受け入れる (監査 F-08 の方針)
    let incoming = endpoint
        .accept()
        .await
        .context("エンドポイントが終了しました")?;
    let conn = incoming.await.context("接続確立に失敗")?;

    // 双方向ストリームを受け入れる
    let (send, recv) = conn.accept_bi().await.context("ストリーム受け入れ失敗")?;

    // SAS ハンドシェイク → SAS 確認 → 本文チャットの順で実行
    run_session(&endpoint, conn, send, recv).await?;

    endpoint.close().await;
    Ok(())
}

/// Connect モード: チケットを取得し、接続を確立する
pub async fn run_connect(opts: ConnectOpts) -> Result<()> {
    // 監査 F-03: チケットを Zeroizing<String> で受け取る
    let ticket_str = read_ticket(&opts).await?;

    let ticket: EndpointTicket = ticket_str
        .trim()
        .parse()
        .context("チケットのパースに失敗 (フォーマット不正)")?;
    let addr = ticket.endpoint_addr();

    let endpoint = build_endpoint().await?;
    let conn = endpoint
        .connect(addr.clone(), ALPN)
        .await
        .context("接続に失敗")?;

    let (send, recv) = conn.open_bi().await.context("ストリーム開設失敗")?;

    run_session(&endpoint, conn, send, recv).await?;

    endpoint.close().await;
    Ok(())
}

/// チケットの取得 (3 通り: 引数 / stdin パイプ / 対話プロンプト)
async fn read_ticket(opts: &ConnectOpts) -> Result<Zeroizing<String>> {
    if let Some(ticket) = &opts.ticket_arg {
        // 監査 F-03: 引数経由は非推奨だが互換のため残す。明示警告を出す。
        eprintln!(
            "[警告] --ticket-arg は非推奨です。チケットが shell history\n\
             や process list に残る可能性があります。\n\
             代わりに `bluewren connect` (対話プロンプト) または\n\
             `... | bluewren connect --ticket-stdin` を使用してください。"
        );
        return Ok(Zeroizing::new(ticket.clone()));
    }

    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    if !opts.ticket_stdin {
        // 対話プロンプト
        print!("チケットを貼り付けてください: ");
        std::io::stdout().flush()?;
    }

    reader
        .read_line(&mut line)
        .await
        .context("チケット読み取り失敗")?;

    if line.trim().is_empty() {
        bail!("チケットが空です");
    }

    Ok(Zeroizing::new(line))
}

/// 接続確立後、SAS ハンドシェイクを行いユーザー確認を待ってから
/// チャットループに入る。
async fn run_session(
    endpoint: &Endpoint,
    conn: Connection,
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
) -> Result<()> {
    // SAS ハンドシェイク
    perform_sas_handshake(endpoint, &conn, &mut send, &mut recv).await?;

    // チャット本体
    chat_loop_with_timeouts(send, recv).await?;

    Ok(())
}

/// SAS ハンドシェイクを実行し、ユーザー確認まで待つ
///
/// 1. 自分の nonce を生成して送信
/// 2. 相手の nonce を受信
/// 3. SAS を計算して表示
/// 4. ユーザーが Enter を押すまで待つ (timeout 付き)
///
/// この関数の完了をもって、本文メッセージのやり取りが安全に開始できる。
async fn perform_sas_handshake(
    endpoint: &Endpoint,
    conn: &Connection,
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
) -> Result<()> {
    let local_nonce = generate_nonce();
    // ADR-0002: ローカル ID は Endpoint::id() から取得 (Connection::local_endpoint_id は廃止)。
    // 相手 ID は HandshakeCompleted 状態の Connection::remote_id() から取得。
    let local_id = endpoint.id();
    let remote_id = conn.remote_id();

    // 自分の nonce を送信
    write_frame(send, FrameType::SasHandshake, &*local_nonce).await?;

    // 相手の nonce を受信 (timeout 付き)
    let remote_frame = timeout(READ_FRAME_TIMEOUT, read_frame(recv))
        .await
        .context("SAS handshake のタイムアウト")??
        .context("接続が SAS handshake 中に閉じられました")?;

    if remote_frame.frame_type != FrameType::SasHandshake {
        bail!("予期しないフレーム型 (SAS handshake 期待)");
    }
    if remote_frame.payload.len() != NONCE_LEN {
        bail!("nonce 長が不正: {} バイト", remote_frame.payload.len());
    }

    let remote_nonce: Zeroizing<Vec<u8>> = Zeroizing::new(remote_frame.payload);

    let sas = compute_sas(
        local_id.as_bytes(),
        remote_id.as_bytes(),
        ALPN,
        &*local_nonce,
        &remote_nonce,
    );
    let formatted = format_sas(sas);

    println!();
    println!("══════════════════════════════════════════════════════════════");
    println!("  ペアリングコード: {}", formatted);
    println!();
    println!("  相手と通話・対面など別経路でこの番号が一致するか確認してください。");
    println!("  一致したら Enter キーを押すとチャットが開始されます。");
    println!("  一致しない場合は Ctrl+C で直ちに終了してください。");
    println!("══════════════════════════════════════════════════════════════");
    print!("確認しました [Enter]: ");
    std::io::stdout().flush()?;

    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();
    timeout(SAS_CONFIRM_TIMEOUT, reader.read_line(&mut line))
        .await
        .context("SAS 確認タイムアウト (120 秒)")??;

    Ok(())
}

/// メインのチャットループ (SAS 確認後に開始)
async fn chat_loop_with_timeouts(
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
) -> Result<()> {
    println!();
    println!("[接続成功] 入力した行が相手に送信されます。/quit で終了。");
    println!();

    let session_start = tokio::time::Instant::now();

    // 受信タスク (idle timeout 付き)
    let recv_task = tokio::spawn(async move {
        loop {
            let result = timeout(IDLE_TIMEOUT, read_frame(&mut recv)).await;
            match result {
                Err(_) => {
                    println!("\n[idle timeout (5分) により切断]");
                    break;
                }
                Ok(Ok(Some(frame))) => match frame.frame_type {
                    FrameType::Message => {
                        let msg = String::from_utf8_lossy(&frame.payload);
                        // 重要: 表示前に必ず sanitize する (監査 F-09 対策)
                        let safe = sanitize_for_terminal(&msg);
                        print!("\r\x1b[K[相手] {}\n> ", safe);
                        let _ = std::io::stdout().flush();
                    }
                    FrameType::Dummy => {
                        // keepalive は表示しない (将来の cover traffic 用)
                    }
                    FrameType::Control => {
                        println!("\n[相手がセッション終了を要求]");
                        break;
                    }
                    FrameType::SasHandshake => {
                        warn!("不適切なタイミングの SAS フレーム (無視)");
                    }
                },
                Ok(Ok(None)) => {
                    println!("\n[接続が閉じられました]");
                    break;
                }
                Ok(Err(e)) => {
                    warn!("受信エラー: {:?}", e);
                    break;
                }
            }
        }
    });

    // 送信ループ + session max duration の監視
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    print!("> ");
    std::io::stdout().flush()?;

    loop {
        // セッション最大時間のチェック (監査 F-08)
        if session_start.elapsed() > SESSION_MAX_DURATION {
            println!("\n[セッション最大時間 (1時間) を超過、終了します]");
            break;
        }

        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break; // EOF (Ctrl+D)
        }
        let trimmed = line.trim_end_matches(&['\n', '\r'][..]);

        if trimmed.is_empty() {
            print!("> ");
            std::io::stdout().flush()?;
            continue;
        }
        if trimmed == "/quit" {
            // 相手に control frame で通知してから終了
            let _ = write_frame(&mut send, FrameType::Control, b"close").await;
            break;
        }
        if trimmed.len() > MAX_PAYLOAD {
            eprintln!("[警告] メッセージが長すぎます ({} バイトまで)", MAX_PAYLOAD);
            print!("> ");
            std::io::stdout().flush()?;
            continue;
        }

        write_frame(&mut send, FrameType::Message, trimmed.as_bytes()).await?;
        print!("> ");
        std::io::stdout().flush()?;
    }

    let _ = send.finish();
    let _ = send.stopped().await;
    recv_task.abort();
    Ok(())
}

#[cfg(test)]
mod tests {
    //! ADR-0002: 揮発的アイデンティティと Builder + ALPN 先行設定の不変条件を検証する。
    //!
    //! 注: これらのテストは UDP ソケットの bind を伴うが、`online()` は呼ばないため
    //! リレー登録のためのネットワーク I/O は発生しない。
    use super::*;

    #[tokio::test]
    async fn endpoint_built_via_builder_with_alpn() {
        // Builder + ALPN 先行設定で bind できること。
        let ep = endpoint_builder()
            .bind()
            .await
            .expect("bind should succeed");
        // EndpointId が取得できること (ADR-0002 の API 名最新化)。
        let _ = ep.id();
        ep.close().await;
    }

    #[tokio::test]
    async fn two_endpoints_have_distinct_ids() {
        // ADR-0002: 揮発的アイデンティティ。同一プロセス内でも独立に
        // bind したエンドポイントは異なる Ed25519 鍵を持ち、EndpointId が一致しない。
        let a = endpoint_builder().bind().await.expect("bind a");
        let b = endpoint_builder().bind().await.expect("bind b");
        assert_ne!(a.id(), b.id(), "別々の bind は別々の EndpointId を持つべき");
        a.close().await;
        b.close().await;
    }
}
