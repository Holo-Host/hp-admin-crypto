# HoloPort Admin Crypto Client

Front-end class for signing messages with ed-25519 keypair that is generated from HoloPort Host's credentials. Created keypair is stored in wasm memory.

## API reference

soon...

## Usage
```javascript
import {HpAdminKeypair} from "hp-admin-crypto-client";

const HC_PUBLIC_KEY = "3llrdmlase6xwo9drzs6qpze40hgaucyf7g8xpjze6dz32s957";
const EMAIL= "pj@abba.pl";
const PASSWORD= "abba";

// Create 
let kp = new HpAdminKeypair(HC_PUBLIC_KEY, EMAIL, PASSWORD);

const payload = {
    method: "get",
    uri: "/someuri",
    body_string: ""
}

console.log(kp.sign(payload));
```


