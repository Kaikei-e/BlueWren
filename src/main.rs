//! BlueWren: 実験的な暗号化 P2P テキストチャット (1対1)
//!
//! エントリポイント。CLI 引数を解釈し、listen / connect モードを起動する。
//! セキュリティに関する詳細は docs/THREAT_MODEL.md と docs/SAFE_USAGE.md を参照。

mod cli;
mod frame;
mod pairing;
mod sanitize;
mod session;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Mode};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // ログ初期化
    // 監査 F-11 対応: デフォルトは warn にし、EndpointId などのメタデータが
    // ログに残らないようにする。詳細ログが必要な場合は明示的フラグを要求。
    let filter = if cli.unsafe_debug_log_metadata {
        eprintln!(
            "[警告] --unsafe-debug-log-metadata: EndpointId 等のメタデータ\n\
             がログに出力されます。本番では使用しないでください。"
        );
        "bluewren=debug,iroh=debug".to_string()
    } else {
        "bluewren=warn,iroh=warn".to_string()
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| filter.into()),
        )
        .with_target(false)
        .init();

    // 起動時の安全な利用に関する注意 (監査 F-06 対応)
    eprintln!(
        "[注意] BlueWren はメッセージ・鍵をディスクに保存しませんが、\n\
         OS / ターミナル / clipboard / swap 等は別問題です。\n\
         詳細は docs/SAFE_USAGE.md を参照してください。"
    );

    match cli.mode {
        Mode::Listen => session::run_listen().await,
        Mode::Connect(opts) => session::run_connect(opts).await,
    }
}
