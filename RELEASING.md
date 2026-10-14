# Release preparation for v0.7.1

| Package | Previous published version | Prepared version |
| --- | --- | --- |
| `dhttp` | 0.7.0 | 0.7.1 |
| `dhttp-home` | 0.6.0 | 0.6.1 |
| `dhttp-access` | 0.5.0 | unchanged |
| `dhttp-log` | 0.2.0 | unchanged |
| `@genmeta/dhttp / dhttpy` | 0.7.0 | 0.7.1 |

## Scope and upgrade

This patch release standardizes the OCSP cache at `ssl/stapling.ocsp`. Identity loading and SDK reloads use this path; the old `ssl/ocsp.der` cache is no longer read. Offline deployments must prepare a valid staple at the new path before loading an identity. With online identity preparation enabled, the existing OCSP preparation validates or refreshes the new cache. No automatic rename or change to OCSP verification is introduced.

The SDK bridge and Node.js/Python binding versions are aligned with dhttp. Multi-platform npm/PyPI publishing remains separate from the crates.io workflow.

## Dependency order

dquic → h3x → dhttp-home → dhttp

Manifest versions use Cargo's compatible-version requirements, without `=`. External Genmeta dependencies come from crates.io; no sibling checkout or Git patch is required. The TLS backend remains qrustls 0.23.45, used as `rustls` where the application exchanges TLS types with qtls.

## Validation and lockfiles

The workspace Cargo.lock is tracked for locked platform checks and publication. Refresh it from the published registry graph outside directories containing ancestor path patches. Preserve unrelated dependency versions; never commit local transport overrides as the release lockfile.

Android builds require qudp 0.8.1 from the dquic v0.8.1 patch release. Retain libc 0.2.189 while nix is incompatible with the Darwin constants removed from iOS in libc 0.2.190.

Before merging and tagging, require the existing formatting, Clippy, test, platform and publish dry-run workflows to pass on the release commit. Local manifest, lockfile and package-content checks do not replace compilation or runtime tests. The dry run handles the new home and dhttp packages together; publication installs dependencies first.

## Publication

Planned tag: `v0.7.1`. After the preparation PR is merged and checks pass, use an annotated tag with the changelog entry as its release notes. Tag-triggered GitHub Actions publishes crates and creates the GitHub Release; preparation does not publish or deploy.

Keep the existing publication order: dhttp-home, dhttp-access, dhttp-log, dhttp. The workflow skips the unchanged access/log versions already on crates.io, so this release publishes dhttp-home 0.6.1 before dhttp 0.7.1.

The dhttp-api bridge is not a crates.io package; Node.js and Python bindings use version 0.7.1. The removed dhttp-identity package is not republished.
