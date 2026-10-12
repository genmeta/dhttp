# Changelog

## [0.7.0] - 2026-10-12

### Changed

- Migrate to independent named Endpoints, anonymous requests and shared QUIC networking.
- Use native HTTP/3 streams, standard bodies, streaming uploads and request trailers.
- Maintain interface bindings and NAT mappings, and evict unusable H3 connections.
- Restore Node.js and Python SDKs; retire the dhttp-identity workspace package.
- Update identity-home, access and log crates for the new API.

### Release versions

| Package | Previous published version | Prepared version |
| --- | --- | --- |
| `dhttp` | 0.6.2 | 0.7.0 |
| `dhttp-home` | 0.5.0 | 0.6.0 |
| `dhttp-access` | 0.4.2 | 0.5.0 |
| `dhttp-log` | 0.1.0 | 0.2.0 |
| `@genmeta/dhttp / dhttpy` | 0.6.2 | 0.7.0 |


## [0.6.2] - 2026-08-19

### Fixed

- Preserve access-rule priority during deduplication, upgrades, and repeated
  rule application.
- Align the production DHTTP bootstrap constants with `dyns`.

### Dependencies

- Release manifests target `dyns` v0.7.2 from crates.io, with `dquic` v0.7.1
  and `h3x` v0.6.1 unchanged.

### Packages

- `dhttp` and `dhttp-api` Rust crates, plus `dhttpy`: v0.6.2
- `dhttp-access`: v0.4.2
- `@genmeta/dhttp`: v0.6.2

## [0.6.1] - 2026-08-11

### Fixed

- Share network-owned mDNS resources across endpoint identities instead of
  opening duplicate multicast bindings.
- Forward service names and address-family constraints through the latest DNS
  lookup contract.

### Dependencies

- Release manifests target `dquic` v0.7.1, `dyns` v0.7.1, and `h3x` v0.6.1.

### Packages

- `dhttp` and `dhttp-api` Rust crates, plus `dhttpy`: v0.6.1
- `dhttp-access`: v0.4.1
- `@genmeta/dhttp`: v0.6.1
