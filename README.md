# hp-admin-crypto
A client for signing and server for verification of calls from HP Admin UI to HPOS.

## server
Server is listening on loopback address `http://127.0.0.1:2884/` for incoming http requests. This service is reading the value of the following headers:
- x-hpos-admin-signature
- x-original-uri

Based on their value verifies if provided signature and `HP Admin key` match the content:
```
{
  "method": ${verb}, // to lowercase, eg. "get"
  "request": ${URI with arguments}, // case sensitive, eg. "/api/v1/config?a=b"
  "body": ${body} // case sensitive, eg. "{\"name\": \"My HoloPort Name\"}"
}
```
`HP Admin Key` is read from the file located via environmental variable `HPOS_STATE_PATH`.

### Development
`nix-shell` sets the environment for development and tests. Just type `nix-shell` from project's root directory.

### Tests
`nix-shell` provides env var `HPOS_STATE_PATH` that points to the test file with HP Admin Key. For all end-to-end tests make sure to either run `hp-admin-crypto-server` from inside the `nix-shell` or provide valid env var `HPOS_STATE_PATH`. Provided test file `hpos-state.json` has been generated with following credentials:
```
	"email": "pj@abba.pl",
	"password": "abba"
```

Unit tests are run by `cargo test`.

### Debugging
`hp-admin-crypto-server` provides robust logging. For logging to `stdout` provide env var `RUST_LOG=debug` while running server.
