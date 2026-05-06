# BlueWren 安全な使い方ガイド

BlueWren v0.2 はアプリ自身ではメッセージや鍵を保存しません。しかし、
利用者の OS・ターミナル・シェル・クリップボード・スワップなど周辺環境には
痕跡が残りうるため、本文書は **高リスク用途** での補助的な hardening 手順を
記述します。これらは BlueWren の責任範囲外ですが、運用上の重要事項です。

## 一般原則

- BlueWren が保護するのは「アプリ層・通信路」までです
- OS / terminal / clipboard / swap / hibernation / IME 履歴は別問題です
- 一切の痕跡を残さない運用を求める場合、本ツールでは不十分です

## チケット共有

チケットは「接続能力」を含む高感度情報です。

**やってはいけないこと**:

- コマンドライン引数に直接渡す (shell history, process list に残る)
- 公開チャネル (公開リポジトリ, twitter, 共有ドキュメントなど) に貼る
- スクリーンショットを SNS にアップロード
- クラウド同期されたメモアプリにペースト

**推奨**:

- 直接対面で QR コード等で渡す
- 既に信頼できる暗号化チャンネル (Signal 等) で送る
- 使い終わったら共有元・共有先の双方で削除する

## ターミナル痕跡の抑制

### shell history を一時的に止める

bash / zsh:

```bash
# 現在のシェルで履歴記録を止める
set +o history

# BlueWren を起動・利用
bluewren listen

# 戻す
set -o history
```

fish:

```fish
function bluewren-private
    set -l old_history $fish_history
    set fish_history ""
    bluewren $argv
    set fish_history $old_history
end
```

### terminal scrollback を消す

利用後にターミナルバッファを破棄するコマンド (環境依存):

```bash
# tmux: 履歴バッファをクリア
tmux clear-history

# 多くのターミナルで使える ANSI シーケンス
printf '\033c\033[3J'

# macOS Terminal.app
# Cmd+K で scrollback を消去

# iTerm2
# Cmd+K
```

## OS レベルの痕跡

### swap 経由の漏洩

メモリ上の鍵やメッセージが swap に書き出されると、ディスク上に残ります。

**対策 (Linux)**:

```bash
# 現在の swap を一時的に無効化 (root 権限)
sudo swapoff -a

# 利用後に再有効化
sudo swapon -a
```

恒久的に swap を使わないか、swap 暗号化を有効化することを検討してください。

### core dump

プロセスがクラッシュした際に core dump が生成されると、メモリ内容が
ディスクに残ります。

**対策**:

```bash
# 現在のシェルで core dump 無効化
ulimit -c 0

# systemd-coredump 抑制 (root 権限・恒久的)
sudo systemctl mask systemd-coredump.socket
```

### hibernation

サスペンド・ハイバネーションが有効な場合、メモリイメージがディスクに
書き出されます。BlueWren 利用中はハイバネーションを避けることを推奨します。

### クリップボード

クリップボード履歴を保持するアプリ (Alfred, Raycast, ClipMenu など) を
使っている場合、ペーストしたチケットが履歴に残ります。BlueWren 利用前に
履歴を一時無効化するか、ペースト後に直ちに履歴を消去してください。

### IME 変換履歴

日本語入力など IME を使うシステムでは、変換候補に過去の入力が残ります。
重要な内容を BlueWren で送る場合、IME 履歴を一時的に無効化する設定を
検討してください。

## ログレベル

BlueWren はデフォルトで `bluewren=warn,iroh=warn` のログレベルで動作し、
EndpointId・relay URL・チケット文字列・SAS・nonce 等のメタデータは出力されません
(ADR-0007)。デバッグ目的で詳細ログが必要な場合のみ、明示的に有効化してください。

```bash
# デバッグ用 (メタデータをログに出す危険な操作)
bluewren --unsafe-debug-log-metadata listen
```

このフラグを使うと、出力をパイプで `tee` 等に繋いだ場合に永続化され、ローカル
受動フォレンジック攻撃者 (脅威モデル A7) の対象になります。トラブルシューティング
完了後は速やかにログファイルを削除してください。

## 利用後のクリーンアップチェックリスト

- [ ] チケットを共有元・共有先の双方で削除
- [ ] terminal scrollback を消去
- [ ] shell history から該当行を削除 (`history -d <num>`)
- [ ] クリップボードをクリア (`pbcopy < /dev/null` 等)
- [ ] core dump があれば削除 (`/var/lib/systemd/coredump/`)
- [ ] swap が活用された可能性があれば、空き領域を再書き込みするか暗号化を確認

## 高リスク用途には専用環境を

ジャーナリズム・人権活動などで真に高リスクな通信を扱う場合、BlueWren
単体では不十分です。Tails OS や Whonix のような匿名化に特化した OS、
あるいは Briar / SimpleX Chat のような別カテゴリのツールを検討してください。
