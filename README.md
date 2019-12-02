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
`HP Admin Key` is read from the file located via environmental variable `HPOS_STATE_PATH`. For local tests outside of the HPOS run `HPOS_STATE_PATH="/your/path/to/hpos-state.json" cargo run`.

