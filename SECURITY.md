# Security Policy

## Scope

BlueWren v0.2 is **experimental software** for short-lived, two-party encrypted text chat.
It is **not** a complete anonymity system.

## What BlueWren tries to protect

- Message contents in transit (via Iroh/QUIC TLS 1.3)
- Direct leakage of short plaintext message length (via 256-byte fixed-length
  application frames; see ADR-0003)
- Session-to-session linkage via long-lived app identity (via ephemeral endpoint
  keys; see ADR-0002)
- Application-level message persistence (no disk writes by the app itself; see
  ADR-0001 non-goals)
- Detection of in-band ticket tampering via a 30-bit SAS / pairing code bound to
  the live TLS session through RFC 5705 keying-material exporters, confirmed by
  user re-entry of the displayed code (see ADR-0004 v2)

## What BlueWren does NOT protect

- IP addresses (visible to peers and to relay operators)
- Traffic timing and volume
- Relay metadata (which two endpoints communicated, when, and roughly how much)
- Endpoint compromise (RAT, malware, root access)
- Memory forensics (RAM dump while running)
- Terminal scrollback, shell history, clipboard manager, swap files,
  hibernation images, OS journal, crash dumps, IME history
- A peer who saves, forwards, or screenshots your messages

## Reporting vulnerabilities

Please report security issues privately by opening a GitHub security advisory
or contacting the maintainer directly. Do not publish exploit details before
a fix is available.

## Dependency advisories

The project must pass the following before any release (see ADR-0008):

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all --all-features --locked
cargo audit
cargo deny check
cargo tree -i quinn-proto    # must resolve to >= 0.11.14
```

Release binaries must be built with `cargo-auditable` (>= 0.7.4) so that the
dependency tree is embedded into the binary and auditable post-distribution:

```bash
cargo auditable build --release --locked
```

CI enforces these checks on every push and pull request, plus a daily
scheduled run to catch newly published RustSec advisories.

## Known limitations

- BlueWren depends on Iroh, which uses QUIC via the `quinn-proto` crate.
  Past advisories (notably **RUSTSEC-2026-0037 / CVE-2026-31812**, an
  unauthenticated remote DoS via panic in QUIC transport-parameter parsing,
  CVSS 8.7 HIGH, fixed in `quinn-proto >= 0.11.14`) have affected QUIC
  parsing logic. We pin and audit transitive dependencies via `Cargo.lock`
  and CI-enforced `cargo audit` / `cargo deny check` / `cargo tree -i quinn-proto`
  (see ADR-0008).
- The default n0 relay infrastructure is operated by Number Zero, Inc.
  Relay operators can observe connection metadata (endpoint id pairs,
  timestamps, approximate volume; see ADR-0005 and threat-model adversary A3).
- Memory zeroization in Rust is best-effort. Compiler optimizations,
  allocator behavior, and OS-level swap can result in residual data; BlueWren
  does **not** claim memory-forensics resistance (see design guidelines §10).

## Disclosure history

(none yet)
