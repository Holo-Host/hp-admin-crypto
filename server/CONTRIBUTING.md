# Contributing

Server is built in `Rust 1.38.0-nightly`.

## Setup
`nix-shell` sets the environment for development and tests. Type `nix-shell` from project's root directory to set up dev environment.

## Build
Build from source with `cargo build`.

## Tests
`nix-shell` comes with preset test env var `HPOS_STATE_PATH` that points to the file with HP Admin Key test value. For all end-to-end tests make sure to either run `hp-admin-crypto-server` from inside the `nix-shell` or pass a valid env var `HPOS_STATE_PATH`. Test file `hpos-state.json` has been generated with the following credentials:
```
	"email": "pj@abba.pl",
	"password": "abba"
```

Unit tests are run with `cargo test`.