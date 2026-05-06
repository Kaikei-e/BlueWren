# ADR-0004: チケット取扱方針と SAS / Pairing Code (v2)

- **ステータス**: 採択 (Accepted, v2)
- **日付**: 2026-05-06 (v1 初版), 2026-05-06 (v2: 設計指針 §4 への追随)
- **関連**: 監査 F-03, F-04 / 設計指針 §4 §8.1 §8.2 §10.1 / ADR-0003 (フレーム) /
  ADR-0007 (ログ境界) / ADR-0009 (timeout)

## コンテキスト

v0.1 ではチケットをコマンドライン引数として受け取る `bluewren connect <ticket>`
形式を採用していた。第一次セキュリティ監査により以下の問題が指摘された。

**F-03**: チケットが shell history、process list (`/proc/<pid>/cmdline`)、
terminal scrollback、screen/tmux ログ、command logger 等に残る。チケットは
secret ではないが、漏洩すると intended peer 以外が接続を試せる高感度情報で
あり、引数渡しは設計上の欠陥である。

**F-04**: Iroh は接続先 EndpointId を暗号学的に認証するが、利用者が受け取った
チケット自体が攻撃者によって差し替えられていた場合、攻撃者の鍵が「正しく」
認証されてしまう。アプリ層での MitM 検出手段が存在しない。

v1 (2026-05-06) では SAS を 20 bit で導入し、Enter キーによる確認 UX を採用
した。しかし第二次セキュリティ監査と設計指針 §4 のレビューにより、以下の
問題が浮上した。

- **20 bit (約 100 万通り)** は単発の目視確認として機能するが、安全性主張の
  中核としては弱い。攻撃者が SAS を偶然一致させる確率が 10^-6 と現実的に
  到達可能なオーダーに残る。
- **Enter キー単発確認** は、利用者が漫然と確認をスキップする事故を構造的に
  許してしまい、SAS の意義そのものを毀損する。
- **SAS の根が EndpointId と nonce のハッシュ** に留まり、実 TLS セッションへ
  バインドされていなかった。これにより、攻撃者が両者と独立に TLS を張った
  状態で同一の SAS を導出する余地が理論上残る。
- 互換フラグ名 `--ticket-arg` には設計指針 §8.2 の `--unsafe-` プレフィクス
  規律が適用されていなかった。

本 v2 ではこれらすべてを是正する。

## 決定

### F-03 への対応 (v2): チケット入力経路

1. **デフォルト**: `bluewren connect` で実行すると、stdin から入力プロンプト
   経由でチケットを受け取る。
2. **パイプ入力**: `printf '%s' "$TICKET" | bluewren connect --ticket-stdin` で
   非対話的に渡せる。
3. **互換モード (危険)**: **`bluewren connect --unsafe-ticket-arg <ticket>`** に
   名称を変更する。設計指針 §8.2 の `--unsafe-` プレフィクス規律により、
   コマンドラインを見ただけで「これは安全な使い方ではない」と利用者に伝わる。
   v0.1 / v1 系で使われていた `--ticket-arg` は **alias を提供しない** (新規
   v0.2 リリース時点での破壊的変更を許容する)。フラグ使用時は起動メッセージで
   明示的な警告を出力する。
4. 受け取ったチケット文字列は `Zeroizing<String>` に格納し、Drop 時にゼロ化
   する。

### F-04 への対応 (v2): TLS exporter ベース SAS

接続確立後、本文メッセージ送信前に以下のフローを実行する。SAS の根として、
QUIC セッションごとに一意な秘密値を引き出す **TLS exporter (RFC 5705 / RFC 8446
§7.5)** を使用する。Iroh の `Connection` には双方が同じ label と context を
指定すると暗号学的に強い同一の擬似乱数列を独立に得られるエクスポータ API が
提供されている (実 API シグネチャは実装着手前に `docs.rs/iroh/latest` と
`cargo check` で検証する)。これにより SAS が単なる EndpointId と nonce の
ハッシュから「実 TLS セッションそのものに紐付いた値」へと格上げされる。

1. 双方が 16 バイトの揮発的 nonce を生成する (`OsRng`)。nonce は `Zeroizing` で
   包む。
2. ALPN ハンドシェイクで開いた双方向ストリームで `SasHandshake` フレーム
   (type `0x04`、ADR-0003) を交換し、互いの nonce を渡す。
3. 双方が **TLS exporter から 32 バイトの keying material** を導出する:

   ```
   exported = Connection::export_keying_material(
       label   = "EXPORTER-bluewren-sas-v2",
       context = b"",
       length  = 32,
   )
   ```

   `exported` は `Zeroizing` で包む。同一 TLS セッション内で双方が同じ値を
   独立に得る。

4. 双方が以下の値を計算する:

   ```
   sas_input =
       "bluewren-sas-v2\0"                                         ||
       len_prefixed(min(EndpointId_a, EndpointId_b))               ||
       len_prefixed(max(EndpointId_a, EndpointId_b))               ||
       len_prefixed(ALPN)                                          ||
       len_prefixed(nonce_corresponding_to_min_id)                 ||
       len_prefixed(nonce_corresponding_to_max_id)                 ||
       len_prefixed(exported)
   sas = BLAKE3(sas_input)[上位 30 ビット]
   ```

   - `len_prefixed(x) = u32_be(x.len()) || x` で concatenation 攻撃を防ぐ。
   - EndpointId は辞書順にソートして連結することで、listen 側と connect 側が
     同一の値を独立に計算できる。nonce も EndpointId の順に対応させる。
   - SAS 値そのものも `Zeroizing` で包む。

5. SAS を **`XXXXX-XXXXX` 形式 (10 進 10 桁、先頭ゼロ埋め)** で表示する
   (30 bit ≈ 1,073,741,823、最大 10 桁)。
6. 利用者は別経路 (通話・対面など) で双方の表示が一致することを確認する。
7. **確認 UX は番号再入力方式** (設計指針 §4.4): 表示された SAS をプロンプトに
   そのまま打ち込ませる。Enter のみで通す UX は採用しない。
8. **入力が SAS と一致した場合のみ** `Control(AckSas)` フレーム (ADR-0003
   §6.5、コード `0x02`) を送信し、相手の `Control(AckSas)` 受信をもって
   本文メッセージのやり取りを開始する。
9. **入力が一致しない場合 / 確認 timeout (120s) 超過 / Ctrl+C / EOF** の場合、
   セッションを直ちに終了する。`Control(Close)` を送信できれば送信し、
   connection を close したのちエンドポイントを終了する。**自動再試行は
   一切提供しない** (設計指針 §4.5。再試行は SAS 偶然一致を試行回数で稼ぐ
   機会となる)。利用者にはチケット交換経路自体の見直しを案内する。
10. **SAS 確認が完了するまで `FrameType::Message` フレームは一切送受しない**
    (設計指針 §4.6)。これは構造的不変条件として実装に組み込む。

### SAS のビット長

**30 bit (約 10 億通り)** を採用する (設計指針 §4.2 推奨値)。攻撃者が SAS を
偶然一致させる確率は約 10^-9 のオーダーになり、現実的な防御として通用する。

下限 24 bit を本 ADR が定める規律として明記し、**それ以下に下げないこと** を
不変条件とする。20 bit への復帰は禁止する。UX 上の譲歩線は 24 bit とする。

将来的に 32 bit 以上、emoji-based SAS (Matrix 風)、PGP word list 風の表現は
別 ADR で検討の余地があるが、いずれも **20 bit 復帰** だけは選択肢から除外する。

### Zeroize 適用範囲 (設計指針 §10.1)

以下を `zeroize::Zeroizing` または `secrecy::SecretBox` で包む:

- 入力されたチケット文字列 (`Zeroizing<String>`)
- 自分の nonce / 相手の nonce (`Zeroizing<[u8; 16]>` / `Zeroizing<Vec<u8>>`)
- TLS exporter から得た keying material (`Zeroizing<[u8; 32]>`)
- 計算後の SAS 値そのもの (表示用 `String` を含む)
- stdin 受信バッファ (best-effort)

機微フィールドを扱うソース箇所には `// [SENSITIVE]` コメントを付け、grep
可能にする (ADR-0007 と整合)。

## 帰結

利点:

- shell history / process list 経由のチケット漏洩を構造的に防げる
- チケットの帯域外経路が侵害された MitM を、利用者が確認段階で検出できる確率が
  10^-6 → 10^-9 に向上する
- SAS が実 TLS セッションへバインドされ、攻撃者が双方と独立に TLS を張った
  状態で同一の SAS を導出することが困難になる
- 番号再入力により、漫然 Enter による確認スキップ事故を構造的に防止する
- `--unsafe-ticket-arg` 命名により、利用者が「危険な選択肢」と即座に認識できる
- Zeroizing 範囲拡大によりメモリ上の機微値残留を best-effort で減らせる
- 計算は BLAKE3 のみで、依存関係を増やさず軽量

代償:

- 利用者が「番号入力」を求められる UX のため、対面ペアリング時にやや手間が
  増える (Enter のみ確認に比べて数秒〜十数秒)
- v0.1 / v1 系の `--ticket-arg` 利用者は v2 リリース時に flag 名変更で破壊的
  影響を受ける (新規 v0.2 でのリリースのため許容)
- TLS exporter API のシグネチャは Iroh のバージョンに依存するため、Iroh 0.98
  系の API に追随する実装が必要 (ADR-0002 の規律に従い `cargo check` で検証)

## 将来の検討事項

- PGP word list 風の単語列表現 (発音可能な英単語ペア) の採用
- emoji-based SAS (Matrix-style: 7 emoji × 6 bit = 42 bit) の採用
- SAS ビット長の引き上げ (32 bit〜)
- 自動 SAS 確認はしない (利用者の能動的確認が SAS の本質)
- **20 bit への復帰** および **Enter のみ確認** は将来も選択肢から除外する
  (本 ADR v2 の不変条件)

## 改訂履歴

- 2026-05-06 (v1): 初版 (SAS 20 bit / Enter 確認 / `--ticket-arg`)
- 2026-05-06 (v2 audit-sync): 設計指針 §4 と第二次セキュリティ監査を反映:
  - SAS: 20 bit → 30 bit (XXXXX-XXXXX)、TLS exporter (RFC 5705) バインド
  - 確認 UX: Enter 単発 → 番号再入力 + `Control(AckSas)` 双方確認
  - 不一致時の即時アボート + 自動再試行禁止を構造化
  - フラグ名: `--ticket-arg` → `--unsafe-ticket-arg`
  - Zeroize 範囲を nonce / SAS / exported keying material / stdin バッファへ拡大
