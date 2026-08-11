# Changelog

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
