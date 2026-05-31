# DHTTP

DHTTP is an HTTP/3 stack for building DHTTP endpoints. This repository contains the Rust SDK crates and native Node.js/Python bindings, plus supporting identity, home, and access-control primitives.

The Rust crates are published as separate packages so lower-level primitives can be consumed independently:

- `dhttp-identity` provides identity primitives.
- `dhttp-home` provides local home and profile management.
- `dhttp-access` provides access-control primitives.
- `dhttp` provides the endpoint SDK.

The native SDK bindings are published separately for Node.js and Python.