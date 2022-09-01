# HoloPort Admin Crypto Server

Server is listening on loopback address `http://127.0.0.1:2884/` for incoming http requests.

Based on value of the following headers
- x-hpos-admin-signature
- x-original-uri
it responds with 200 or 401. Signature is checked against `HP Admin Key`. The value of `HP Admin Key` is read from the file located via environmental variable `HPOS_STATE_PATH`.

## Code logic
```mermaid
flowchart TD
    A(check if X-auth-token header is set)
    A-->|no|C
    A-->|yes|G
    G(check if X-signature header is set)
    G-->|yes|J
    J(verify signature)
    J-->|ok|H
    H(save auth-token in memory)
    J-->|fail|K
    K(return 401)
    H-->I
    I(return 200)
    G-->|no|B
    B(check auth-token aginst in-memory)
    B-->|fail|D
    D(return 401)
    B-->|ok|E
    E(save auth-token's new create time)
    E-->L
    L(return 200)
    C(return 401)
```

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