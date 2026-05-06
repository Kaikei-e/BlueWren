//! CLI 引数の定義
//!
//! 監査 F-03 への対応:
//! - チケットは stdin プロンプトで受け取るのがデフォルト
//! - パイプ入力は `--ticket-stdin` (この場合プロンプトは表示せず stdin から1行読む)
//! - 互換のため `--ticket-arg` を残すが、起動時に明示警告を出す

use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "bluewren",
    version,
    about = "実験的暗号化 P2P テキストチャット (1対1)",
    long_about = "\
BlueWren は、二者間の短時間テキスト通信に特化した OSS チャットです。\n\
Iroh/QUIC による暗号化通信、揮発的アイデンティティ、固定長フレーム、\n\
帯域外チケット交換、SAS による相手認証を組み合わせます。\n\
\n\
これは完全な匿名通信ツールではありません。IP アドレス、通信タイミング、\n\
端末上の痕跡などは保護しません。docs/THREAT_MODEL.md を参照してください。"
)]
pub struct Cli {
    /// EndpointId などのメタデータをログに出力する (デバッグ用、本番禁止)
    #[arg(long, global = true)]
    pub unsafe_debug_log_metadata: bool,

    #[command(subcommand)]
    pub mode: Mode,
}

#[derive(Subcommand, Debug)]
pub enum Mode {
    /// 接続を待ち受ける。起動するとチケットが表示される。
    Listen,
    /// チケットを指定して接続する。
    Connect(ConnectOpts),
}

#[derive(Args, Debug)]
pub struct ConnectOpts {
    /// stdin から 1 行だけ読み取る (パイプ入力用)
    #[arg(long, conflicts_with = "ticket_arg")]
    pub ticket_stdin: bool,

    /// チケットをコマンドライン引数で渡す (非推奨: shell history に残ります)
    #[arg(long, value_name = "TICKET")]
    pub ticket_arg: Option<String>,
}
