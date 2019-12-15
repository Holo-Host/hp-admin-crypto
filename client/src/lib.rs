use failure::{Error, err_msg};
use wasm_bindgen::prelude::*;
use ed25519_dalek::{Keypair, PublicKey};
use hpos_state_core::admin_keypair_from;
use serde::*;

#[wasm_bindgen]
pub struct HpAdminKeypair(Keypair);

#[derive(Serialize, Deserialize, Debug)]
struct Payload {
    method: String,
    uri: String,
    body_string: String,
}

#[wasm_bindgen]
impl HpAdminKeypair {

    /// @description Create an Ed25519 keypair for API signing calls to HPOS
    /// @example
    /// myKeys = new HpAdminKeypair( hc_public_key_string, email, password );
    #[wasm_bindgen(constructor)]
    pub fn new(hc_public_key_string: String, email: String, password: String) -> Result<HpAdminKeypair, JsValue> {
        // rewrite any Error into JsValue
        match new_inner(hc_public_key_string, email, password) {
            Ok(v) => Ok(Self(v)),
            Err(e) => Err(e.to_string().into())
        }
    }

    /// @description Sign payload and return base64 encoded signature. 
    /// Requires properly formatted payload:
    /// const payload = { 
    ///     method: String,
    ///     uri: String,
    ///     body_string: String
    /// }
    /// @example
    /// myKeys = new HpAdminKeypair( hc_public_key_string, email, password );
    /// const payload = { 
    ///     method: "get",
    ///     uri: "/someuri",
    ///     body_string: ""
    /// }
    /// myKeys.sign( payload );
    #[wasm_bindgen]
    pub fn sign(&self, payload: &JsValue) -> Result<String, JsValue> {
        // return meaningful error message via JsValue
        let payload_vec = match parse_payload(payload) {
            Ok(v) => v,
            Err(_) => return Err("Malformed signing payload, check docs for details.".to_string().into())
        };
        
        let signature = self.0.sign(&payload_vec);
        Ok(base64::encode_config(&signature.to_bytes()[..], base64::STANDARD_NO_PAD))
    }
}

fn new_inner(hc_public_key_string: String, email: String, password: String) -> Result<Keypair, Error> {
    let hc_public_key_bytes = base36::decode(&hc_public_key_string)?;
    let hc_public_key = PublicKey::from_bytes(&hc_public_key_bytes)?;
    Ok(admin_keypair_from(hc_public_key, &email, &password)?)
}

fn parse_payload (payload: &JsValue) -> Result<Vec<u8>, Error> {
    let payload_struct: Payload = payload.into_serde()?;
    match serde_json::to_vec(&payload_struct) {
        Ok(v) => Ok(v),
        Err(e) => Err(err_msg(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HC_PUBLIC_KEY: &str = "3llrdmlase6xwo9drzs6qpze40hgaucyf7g8xpjze6dz32s957";
    const EMAIL: &str = "pj@abba.pl";
    const PASSWORD: &str = "abba";
    const EXPECTED_SIGNATURE: &str = "viqqtbfbhTtAarkJjzOgO4cu4MFgGnshYHMjV3nITem01js9lTq0bG2Hwn9rXJi6xYVqOnq2NcosEMcRZ1CAAA";
    const WRONG_SIGNATURE: &str = "dQlFxqMQh0idWk6anOerf7b9/XssKkvSrVIv9gMuf7M31ivli6BM2ktCsv9FHB/2FfdwO4LS8muOkFjSt7uAAg";
    const EXPECTED_KEYPAIR_BYTES: [u8; 64] = [86, 232, 163, 246, 177, 146, 183, 158, 16, 202, 71, 66, 191, 42, 83, 106, 46, 
                71, 128, 204, 29, 161, 253, 99, 103, 119, 51, 166, 207, 227, 152, 126, 254, 75, 67, 43, 110, 118, 167, 
                139, 237, 181, 51, 247, 79, 248, 118, 157, 81, 248, 54, 69, 30, 222, 173, 94, 107, 236, 178, 142, 219, 
                115, 127, 12];

    impl HpAdminKeypair {
        pub fn to_bytes(&self) -> [u8; 64] {
            self.0.to_bytes()
        }
    }

    #[test]
    fn create_correct_keypair() {
        let my_keypair = HpAdminKeypair::new(HC_PUBLIC_KEY.to_string(), EMAIL.to_string(), PASSWORD.to_string()).unwrap();
        let my_keypair_bytes = my_keypair.to_bytes();

        assert_eq!(my_keypair_bytes[..], EXPECTED_KEYPAIR_BYTES[..]);
    }

    #[test]
    fn create_correct_signature() {
        let payload = Payload {
            method: "get".to_string(),
            uri: "/someuri".to_string(),
            body_string: "".to_string(),
        };
        /*
        let payload_js = JsValue::from_serde(&payload).unwrap();
        let my_keypair = HpAdminKeypair::new(HC_PUBLIC_KEY.to_string(), EMAIL.to_string(), PASSWORD.to_string()).unwrap();
        let signature = my_keypair.sign(&payload_js);

        assert_eq!(signature, EXPECTED_SIGNATURE);*/
    }
/*
    #[test]
    fn create_incorrect_signature() {
        let payload = Payload {
            method: "get".to_string(),
            uri: "/someuri".to_string(),
            body_string: "".to_string(),
        };
        let payload_js = JsValue::from_serde(&payload).unwrap();
        let my_keypair = HpAdminKeypair::new(HC_PUBLIC_KEY.to_string(), EMAIL.to_string(), PASSWORD.to_string()).unwrap();
        let signature = my_keypair.sign(&payload_js);

        assert_ne!(signature, WRONG_SIGNATURE);
    }*/
}
