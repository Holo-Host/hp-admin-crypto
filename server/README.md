# HoloPort Admin Crypto Server

Server is listening on loopback address `http://127.0.0.1:2884/` for incoming http requests. It is reading the value of the following headers:
- x-hpos-admin-signature
- x-original-uri

In the absence of the x-hpos-admin-signature header server is looking for a query parameter `X-Holo-Admin-Signature` (both key and value case-sensitive) and uses a value for signature.

Based on their x-original-uri and signature service verifies if the signature and `HP Admin key` match the content:
```
{
  "method": ${verb}, // to lowercase, eg. "get"
  "request": ${URI with arguments}, // case sensitive, eg. "/api/v1/config?a=b"
  "body": ${body} // case sensitive, for empty body can be set to js `undefined`, eg. "{\"name\": \"My HoloPort Name\"}"
}
```
The value of `HP Admin Key` is read from the file located via environmental variable `HPOS_STATE_PATH`.

## Usage
Compile:
```
nix-shell
cargo build
```

Run:
```
./hp-admin-crypto-server
```

## Logging
`hp-admin-crypto-server` provides robust logging via rust's `env_logger` crate. Run with `RUST_LOG=debug` for detailed logging to `stdout`.