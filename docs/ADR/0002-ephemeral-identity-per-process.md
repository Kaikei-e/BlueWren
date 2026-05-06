# ADR-0002: 揮発的アイデンティティの採用

- **ステータス**: 採択 (Accepted) / 実装済み (Implemented in v0.2)
- **日付**: 2026-05-06 (初版), 2026-05-06 (v0.2 audit-sync), 2026-05-06 (v0.2 implemented)
- **関連**: ADR-0001 (スコープ), ADR-0004 (SAS), ADR-0009 (timeout / stream)

## コンテキスト

P2P チャットアプリにおけるアイデンティティ設計は大きく二つに分かれる。

1. **永続的アイデンティティ**: 鍵を保存し、複数セッションで同じ EndpointId
   を使う（例: Signal, Briar）
2. **揮発的アイデンティティ**: セッション毎に鍵を再生成し、過去との紐付けを
   断つ（例: SimpleX のセッション識別子）

永続的アイデンティティは「同じ相手と再び話す」体験を可能にし、信頼の蓄積に
向く。一方で、鍵の漏洩や端末押収によって過去の全活動が同一人物に帰属付け
られるリスクを持つ。

揮発的アイデンティティは、セッション間の暗号学的な紐付けを断つことで
過去のセッションへの遡及帰属を構造的に困難にする。代償として「昨日と同じ
人物か」を BlueWren 自身は確認できない (ADR-0004 の SAS で人間の確認に委ねる)。

## 決定

BlueWren v0.2 では揮発的アイデンティティのみを採用する。

### 鍵の生成と保持

- プロセス起動時に Iroh が内部で新規 Ed25519 鍵を生成する
- 鍵はメモリ上のみで保持され、ディスク・設定ファイル・OS キーリング・環境変数等への
  保存は行わない
- 設定ファイルや鍵リングの概念を持たない

### Iroh エンドポイント構築の規律

設計指針 §5.2 / §5.6 と整合する形で、エンドポイント構築は次の規律に従う。

- **Builder + ALPN 先行設定**: `Endpoint::builder(presets::N0).alpns(vec![ALPN.to_vec()])`
  のように preset と ALPN を bind 前に確定する。短縮形 `Endpoint::bind().await` は
  「どの ALPN を受け入れるか」が構築時の不変属性として明示されないため使用しない。
  ALPN を bind 後に追加する経路はレース条件を生む可能性がある。
- **Iroh API 名の追随**: 旧名称 `NodeId` / `NodeAddr` / `endpoint.node_addr()` /
  `conn.local_endpoint_id()` は廃止または非公開である。本 ADR と実装は
  `EndpointId` / `EndpointAddr` / `Endpoint::id()` / `Endpoint::addr()` /
  `Connection::remote_id()` を正とする。新規バージョン追従時は必ず
  `docs.rs/iroh/latest` と `cargo check` を併用して実 API を検証する。
- 接続シーケンス順序の保証 (open_bi 直後の最初のフレーム送信、accept_bi
  の timeout 付き待機) は ADR-0009 で規定する。

### 鍵を「使う」と「触れる」の境界 (設計指針 §3.3)

秘密鍵そのものは Iroh のエンドポイント API 内部で管理され、アプリケーション
コードが鍵バイト列を直接扱う場面は最小化する。鍵を直接扱うほど、メモリ上の
残留・ログへの混入・デバッガでの露出といった経路で漏洩するリスクが高まる。
アプリ側で鍵を扱う必要が生じた場合は、その必要性を ADR で正当化したうえで、
`zeroize::Zeroizing` または `secrecy::SecretBox` のラッパで保護する。

### 長期鍵の取扱い

長期鍵の導入は v0.2 の範囲外である (ADR-0001 非目標)。将来検討する場合も、
必ずオプトインとし、デフォルトは揮発のまま維持する。長期鍵を導入する場合は、
保存先・暗号化方式・パスフレーズ要件・バックアップ・回転・失効の全側面を
設計し、本 ADR と脅威モデルを大きく改訂する必要がある。これらを設計しない
まま「便利だから」という理由で長期鍵を入れることは禁止する。

## 実装

ADR-0002 の決定事項は `src/session.rs` で実現される。

- **`endpoint_builder()` ヘルパ** (`src/session.rs`): `Endpoint::builder(presets::N0).alpns(vec![ALPN.to_vec()])` を一箇所に集約。プロダクションパスとテストパスの双方が同一の Builder を経由する。短縮形 `Endpoint::bind()` の実呼び出しが存在しないことは
  ```
  grep -nE 'Endpoint::bind\(\)' src/
  ```
  に該当行がないこと（doc コメントは除く）で機械的に検証する。
- **API 名最新化**: ローカル ID は `Endpoint::id()`、相手 ID は `Connection::remote_id()`。旧名 `local_endpoint_id` / `remote_endpoint_id` / `node_addr` の実呼び出しは存在しない。
- **揮発性の検証** (`#[cfg(test)] mod tests` in `src/session.rs`):
  - `endpoint_built_via_builder_with_alpn`: Builder + ALPN 先行設定で bind が成功し、`endpoint.id()` で EndpointId を取得できる。
  - `two_endpoints_have_distinct_ids`: 同一プロセス内で独立に bind した 2 endpoint が異なる EndpointId を持つ（鍵の独立生成）。
- **鍵境界**: アプリコードは秘密鍵バイト列を直接扱わない。`grep -nE 'secret_key|SecretKey|to_bytes\b' src/` がヒット 0 件であることが、現状アプリ層に `Zeroizing` / `SecretBox` ラップ箇所が不要であることの根拠。今後アプリ層が鍵バイト列に触れるコードを追加する場合は、このヒット 0 件の不変条件を破ることになるため、本 ADR を再評価する。

## 帰結

利点:

- 過去のセッションと現在のセッションを暗号学的に結びつけられない
- 鍵管理の複雑さがゼロになる（鍵リング、エクスポート、回転などが不要）
- 押収時のフォレンジック耐性が高い（RAM ダンプ以外では鍵を復元できない）
- Builder + ALPN 先行設定により「受け入れる ALPN」が構築時不変属性となり、
  接続確立後に ALPN を変更する経路が構造的に閉じる

代償:

- 「同じ相手と再び話す」場合、毎回チケット交換 + SAS 確認が必要
- 帯域外チケット交換と SAS 確認が信頼の根拠となる
- Iroh API の破壊的変更時は本 ADR と実装を同時に追随させる必要がある

## 将来の検討事項

利用者が任意で長期鍵を保存しオプトインで使う方式は v0.3 以降で検討の余地が
ある。ただし、その場合は本 ADR を更新するか別 ADR で上書きし、脅威モデル
への影響を明示すること。

## 改訂履歴

- 2026-05-06 (v0.1): 初版 (揮発鍵 / Endpoint::bind() 短縮形)
- 2026-05-06 (v0.2 audit-sync): Builder + ALPN 先行設定を「決定」に格上げ。
  Iroh API 名 (EndpointId / EndpointAddr / Endpoint::id / Connection::remote_id) を最新化。
  「鍵を使う/触れる境界」と zeroize / secrecy ラップ規律を明示。
- 2026-05-06 (v0.2 implemented): `src/session.rs::endpoint_builder` で Builder + ALPN 先行設定を実装。
  `Endpoint::id()` / `Connection::remote_id()` への移行完了。揮発鍵の独立性を
  `#[cfg(test)] mod tests` の 2 テストで検証。`grep` ベースの不変条件 (短縮形 / 廃止 API / 秘密鍵バイト列の出現 0 件) を
  「実装」セクションに記載。
