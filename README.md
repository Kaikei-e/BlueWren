# BlueWren

> Experimental encrypted P2P text chat designed for short-lived, one-to-one sessions with out-of-band ticket exchange

BlueWren is an OSS chat focused on short text conversations between two parties.
By combining Iroh/QUIC encrypted transport, an ephemeral per-process identity,
fixed-length application frames, and user-driven out-of-band ticket exchange,
it provides **confidentiality of message contents** and
**reduced leakage of raw message length**.

## Important caveats

**BlueWren v0.2 is not a fully anonymous communication tool.** It does *not* protect against:

- IP address exposure
- Traffic timing and volume analysis
- The fact that a relay is in use
- Traces left on the device, OS, terminal, clipboard, swap, or core dumps
- Memory forensics (e.g. RAM dumps)
- A compromised ticket-sharing channel (though SAS lets the user detect this)
- Storage, forwarding, or screenshots of message contents by the remote peer

See [docs/principles/THREAT_MODEL.md](docs/principles/THREAT_MODEL.md) and
[docs/principles/SAFE_USAGE.md](docs/principles/SAFE_USAGE.md) for details.

## Design pillars

- **Ephemeral identity**: a fresh endpoint key is generated on every process start (ADR-0002)
- **Out-of-band rendezvous**: tickets are shared by the user through a separate trusted channel (ADR-0004)
- **Fixed-length application frames**: 256 B frames reduce direct leakage of message length (ADR-0003)
- **TLS-exporter-bound SAS verification**: a 30-bit pairing code (`XXXXX-XXXXX`),
  bound to the live TLS session via RFC 5705 keying-material exporters, is
  compared and re-entered after connection to detect ticket substitution (ADR-0004 v2)
- **Non-persistence (application layer)**: message history, keys, and tickets are never written to disk (ADR-0001)
- **Structural timeouts and stream limits**: every async point has a timeout, and the connection is hardened to one bidirectional / zero unidirectional streams (ADR-0009)
- **Auditable supply chain**: `Cargo.lock` is committed, `cargo audit` / `cargo deny check` are CI-required, and release binaries are built with `cargo auditable build --release --locked` (ADR-0008)

## Build

```bash
cargo build --release
```

## Usage

Listening side:

```bash
bluewren listen
```

Connecting side (reads the ticket from stdin by default):

```bash
bluewren connect
# Paste ticket: <paste here>
```

Once connected, both sides display the same 30-bit pairing code in
`XXXXX-XXXXX` format. Verify the match through a separate channel (e.g. a
phone call), then **type the displayed code back into the prompt** (a plain
Enter is not accepted). If the code does not match, abort the session
immediately — no automatic retry is provided (see ADR-0004 v2).

End the chat with `/quit` or Ctrl+D.

### Passing the ticket on the command line is discouraged

```bash
# Not recommended: leaves traces in shell history / process list
bluewren connect --unsafe-ticket-arg <ticket>
```

The `unsafe-` prefix is intentional: the flag exists for compatibility but
emits a startup warning each time it is used (see ADR-0004 v2 §F-03).

## Security audit

Always run the following before a release (see ADR-0008 for the rationale):

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all --all-features --locked
cargo audit
cargo deny check
cargo tree -i quinn-proto    # must resolve to >= 0.11.14 (RUSTSEC-2026-0037)
```

Build release binaries with `cargo-auditable` so the dependency tree is
embedded into the binary for post-distribution audit:

```bash
cargo auditable build --release --locked
```

The same checks run in CI (`.github/workflows/security.yml`), plus a daily
scheduled run to catch newly published RustSec advisories.

## Documentation

- [docs/principles/THREAT_MODEL.md](docs/principles/THREAT_MODEL.md) — formal threat model
- [docs/principles/SAFE_USAGE.md](docs/principles/SAFE_USAGE.md) — safe usage guide
- [docs/principles/BlueWren_v0_2_design_guidelines.md](docs/principles/BlueWren_v0_2_design_guidelines.md) — design guidelines (invariants and forbidden patterns)
- [docs/ADR/](docs/ADR/) — architecture decision records
- [SECURITY.md](SECURITY.md) — security policy

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual-licensed as above, without any additional terms or
conditions.
