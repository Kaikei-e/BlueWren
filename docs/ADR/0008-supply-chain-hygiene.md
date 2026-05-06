# ADR-0008: サプライチェーン hardening

- **ステータス**: 採択 (Accepted)
- **日付**: 2026-05-06
- **関連**: 設計指針 §11 / SECURITY.md / `Cargo.toml` / `deny.toml` /
  `.github/workflows/security.yml`

## コンテキスト

BlueWren は QUIC・TLS・暗号プリミティブを内部に持つ依存ライブラリ群 (`iroh`、
`quinn-proto`、`rustls`、`blake3`、`zeroize`、`secrecy` 等) の上に構築されて
おり、これらは半年で API が変わる領域である。さらに、QUIC 周辺のクレートには
継続的にセキュリティアドバイザリが発行されている。直近の例として、
**RUSTSEC-2026-0037 / CVE-2026-31812** が `quinn-proto < 0.11.14` の
DoS (panic-on-untrusted-input) 脆弱性として 2026-03-09 に公開されている
(CVSS 8.7 HIGH)。

サプライチェーンの hardening を CI と運用ルールで継続的に担保しないと、
セキュリティ表現とコードの実態がずれ、第三次セキュリティ監査で「監査済み」
と称せない状態になる。

## 決定

### Cargo.lock の必須コミット (設計指針 §11.1)

BlueWren は CLI アプリケーション (バイナリ crate) であるため、`Cargo.lock`
は必ずリポジトリにコミットする。ライブラリと異なり、配布されるバイナリは
特定の依存解決結果に基づいてビルドされるべきである。lockfile がない状態で
「監査済み」とは決して言えない。lockfile は依存関係の再現性とサプライチェーン
監査の前提である。

### cargo-audit と cargo-deny の CI 必須化 (設計指針 §11.2)

毎日定時 + すべての PR で `cargo audit` と `cargo deny check` を CI で実行
する。これにより、新しい RustSec advisory が公開された日のうちに影響を
検知できる。

`deny.toml` の現行設定 (本 ADR で正式化):

```toml
[advisories]
vulnerability = "deny"
unmaintained  = "warn"
yanked        = "deny"
notice        = "warn"
ignore        = []  # 例外を入れる場合は ID を明示し、本 ADR にも理由を記載

[bans]
multiple-versions = "warn"
wildcards         = "deny"

[licenses]
unlicensed              = "deny"
copyleft                = "warn"
default                 = "deny"
allow-osi-fsf-free      = "either"
confidence-threshold    = 0.8

[sources]
unknown-registry = "deny"
unknown-git      = "deny"
allow-registry   = ["https://github.com/rust-lang/crates.io-index"]
allow-git        = []
```

これらが PR で fail する場合は、修正なしにマージしない。

### quinn-proto の transitive 監視 (設計指針 §11.3)

QUIC ベースである以上、`quinn-proto` のバージョンには特に注意する。
**`quinn-proto >= 0.11.14`** (RUSTSEC-2026-0037 / CVE-2026-31812 の修正版)
を維持する。CI で次を実行し、ビルドごとに記録する:

```bash
cargo tree -i quinn-proto
```

解決されたバージョンが `< 0.11.14` の場合、CI は fail し、依存更新で
`>= 0.11.14` に追随できないかぎりリリースしない。

### cargo-auditable による配布バイナリ監査可能性 (設計指針 §11.4)

リリースバイナリは **`cargo auditable build --release --locked`** でビルド
する (cargo-auditable >= 0.7.4)。これによりバイナリそのものに依存関係情報
(JSON) が dedicated linker section に埋め込まれ、後から `cargo audit bin` で
配布バイナリの脆弱性チェックが可能になる。これは利用者がバイナリを受け取った
時点でも「このバイナリの依存関係は監査可能である」という保証を提供する。

`--locked` を併用することで、`Cargo.lock` の解決結果と一致する再現性ある
ビルドを保証する。

### 依存追加時のチェックリスト

新しい crate を `Cargo.toml` に追加する PR は、以下を満たすことを必須とする:

1. **必要性の正当化**: 本 ADR / 設計指針 §11 / 該当する別 ADR で必要性を
   述べる
2. **メンテナンス状況の確認**: `crates.io` の最終更新日 / GitHub の活動状況 /
   security advisory の有無
3. **ライセンス整合性**: `deny.toml` の `licenses.allow` に含まれること
4. **wildcard 依存の禁止**: バージョン指定は最低 `major.minor` まで固定する
5. **transitive 依存の確認**: `cargo tree` で間接依存を点検し、`quinn-proto`
   等の既知監視対象が新規追加されていないか確認
6. `cargo audit` / `cargo deny check` が pass すること

## 帰結

利点:

- リリースバイナリの依存関係が後から監査可能になる
- 既知 advisory (RUSTSEC-2026-0037 等) の影響を CI で日次検出できる
- ライセンス・unknown registry / git 経由の依存を構造的に弾ける
- v0.2.0 リリースゲート (設計指針 §13) のチェック項目を CI で機械化できる

代償:

- CI 実行時間が増える (cargo audit / cargo deny / cargo tree)
- 依存追加時のレビュー負荷が上がる (許容: 表面積を増やす判断を慎重にするため)
- cargo-auditable は依存ツリー JSON 分のバイナリサイズ増加を招く (実用上は
  軽微)

## 将来の検討事項

- SBOM (CycloneDX / SPDX) の自動生成と GitHub Release への添付
- Sigstore / cosign を使ったリリースバイナリの署名と検証
- `cargo vet` による依存監査の継続化 (Mozilla / Google ベースライン採用)
- supply-chain levels for software artifacts (SLSA) への準拠検討

## 改訂履歴

- 2026-05-06: 初版 (設計指針 §11 を ADR 化、RUSTSEC-2026-0037 を本 ADR で監視
  対象として正式化、cargo-auditable >= 0.7.4 をリリースビルドに必須化)
