# ADR-0005: リレーとメタデータ境界

- **ステータス**: 採択 (Accepted)
- **日付**: 2026-05-06 (初版), 2026-05-06 (v0.2 audit-sync)
- **関連**: 監査 F-05 / 設計指針 §5.5 / ADR-0001

## コンテキスト

Iroh の P2P 接続は、可能であれば direct connection、不可能ならば relay 経由
で確立される。デフォルトでは Number Zero, Inc. が運用する公開リレー (n0
preset) が使われる。

Iroh のリレーは暗号化されたパケットしか forwarding しないが、運用者は次の
情報を観測できる。

- どの EndpointId が relay に登録した事実
- ある EndpointId とある EndpointId が通信した事実
- いつ通信したか
- おおよその通信量
- relay fallback が継続しているか
- 接続の同時性

第一次セキュリティ監査 F-05 はこの点を「BlueWren が IP 匿名化を提供しないのに
匿名性を主張するのは過大表現」と指摘した。

## 決定

### v0.2 での扱い

1. README / `docs/principles/THREAT_MODEL.md` に「Iroh モードは IP 匿名化を
   提供しない」と明記する。
2. デフォルトリレー使用時のメタデータ可視性を A3 (中継リレー観測者) として
   明示する。
3. Tor / I2P 統合は本リリースの範囲外であることを明記する (ADR-0001 非目標)。
4. リレー切替えのための CLI フラグ設計 (`--relay-mode`) は v0.2 では未実装、
   本 ADR で設計方針のみ確定する。
5. **Tor / I2P 統合を将来導入する場合、Iroh モードと同じ「匿名性」ラベルで
   混合せず、別実行モードとして分離する** (設計指針 §5.5)。同じ「匿名性
   モード」というラベルで複数のモードをまとめると、それぞれの脅威モデルが
   曖昧になる。

### `--relay-mode` 設計方針 (v0.3 以降で実装)

```
bluewren listen [--relay-mode <MODE>]
bluewren connect [--relay-mode <MODE>]

MODE:
  default   ... Number Zero 公開リレー (n0 preset)
  custom    ... 利用者指定の URL を使う (--relay-url <URL>)
  disabled  ... リレーを使わない (direct connection が成立しないと失敗)
```

各モードの脅威モデル:

- `default`: 中央集権的リレー運用者がメタデータを観測可能
- `custom`: 利用者またはコミュニティが運用するリレーを信頼境界とする
- `disabled`: リレー観測者の脅威は消えるが、NAT 越えに失敗すると接続不可

### 別実行モード (Tor / I2P) の分離

将来 Tor / I2P 統合を行う場合、Iroh モードと Tor/I2P モードを **同じ
「匿名性」として混ぜない**。具体的には以下のようなコマンド分離を採用する。

```
bluewren iroh listen
bluewren iroh connect
bluewren onion listen
bluewren onion connect
```

それぞれを `docs/principles/THREAT_MODEL.md` の別セクションで定義し、UX も
失敗条件も別物として扱う。「匿名性のためなら何でもオン」という設計は、
結果として何も保証できない状態を生む。

### Iroh API 名 (現行: 0.98 系)

本 ADR で言及する識別子は次のとおり最新化する (ADR-0002 と整合)。

- `EndpointId` (旧: `NodeId`)
- `EndpointAddr` (旧: `NodeAddr`)
- `Endpoint::id()` でローカル ID 取得
- `Connection::remote_id()` でリモート ID 取得
- `Endpoint::addr()` または `Endpoint::watch_addr().get()` でアドレス取得

## 帰結

利点:

- 匿名性を主張する範囲が明確になる
- リレー運用者の脅威モデルが文書化される
- 将来の Tor 統合で、既存の Iroh モードとの境界が混乱しない
- 利用者が自分のリスクに応じてモード選択できる (将来)

代償:

- v0.2 では `--relay-mode` 自体は未実装で、ADR としての記録に留まる
- Tor / I2P 統合は別途大きな実装コストがかかる (`arti-client` 統合など)

## 将来の検討事項

- v0.3 で `--relay-mode disabled` の実装 (NAT 越え成功率の実測も必要)
- v0.3 で `--relay-mode custom` の実装 (`iroh-relay` を独自運用する手順の文書化)
- v0.4 以降で Tor/I2P モードの設計と実装 (別 ADR を起票)
- カスタムリレーを運用する場合のリレー側 hardening (ログ抑制、TLS 設定等)

## 改訂履歴

- 2026-05-06 (初版): 第一次セキュリティ監査 F-05 を反映
- 2026-05-06 (v0.2 audit-sync): Iroh 0.98 系の API 名 (EndpointId/EndpointAddr/
  Endpoint::id/Connection::remote_id) に追随。Tor/I2P 別実行モード分離方針を
  「決定」§ に再強調。
