# Release preparation for v0.7.0

| Package | Previous published version | Prepared version |
| --- | --- | --- |
| `dhttp` | 0.6.2 | 0.7.0 |
| `dhttp-home` | 0.5.0 | 0.6.0 |
| `dhttp-access` | 0.4.2 | 0.5.0 |
| `dhttp-log` | 0.1.0 | 0.2.0 |
| `@genmeta/dhttp / dhttpy` | 0.6.2 | 0.7.0 |

## Dependency order

dquic → h3x

Manifest versions use Cargo's compatible-version requirements, without `=`.
They allow patch updates within the selected 0.x series. External Genmeta
dependencies come from crates.io; no sibling checkout or Git patch is required.
The dquic TLS backend is the published qrustls 0.23.45 package, used as `rustls`
where the application exchanges TLS types with qtls.

## Validation and lockfiles

This PR is release preparation. Unpublished upstream versions can make CI fail;
such failures do not confirm compilation, tests or package verification.
For tracked lockfiles, run `cargo generate-lockfile` after upstream publication,
review and commit the resulting registry lockfile before tagging.
Run Cargo from a checkout outside directories containing ancestor path patches.
Never commit a lockfile generated with local transport path overrides as the
registry release lockfile. Re-run the normal CI checks and publish dry run after
upstream publication and lockfile refresh; merge and tag only that checked commit.

## Publication

Planned tag: `v0.7.0`. Release through the repository's GitHub Actions workflow.
Use an annotated tag with the changelog entry as its release notes. Actual
publication and production deployment remain separate from this preparation PR.

Publish crates in order: dhttp-home, dhttp-access, dhttp-log, dhttp.
The dhttp-api bridge is not a crates.io package; Node.js and Python bindings
use version 0.7.0. The removed dhttp-identity package is not republished.

The workspace Cargo.lock is tracked for locked platform checks and publication.
Refresh it from the published registry graph before each release.

Android builds require qudp 0.8.1 from the dquic v0.8.1 patch release.
The registry lockfile retains libc 0.2.189 while nix is incompatible with the
Darwin constants removed from iOS in libc 0.2.190.
