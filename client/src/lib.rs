use ed25519_dalek::{Keypair, PublicKey};
use failure::{err_msg, Error};
use hpos_config_core::admin_keypair_from;
use serde::*;
use wasm_bindgen::prelude::*;

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
    pub fn new(
        hc_public_key_string: String,
        email: String,
        password: String,
    ) -> Result<HpAdminKeypair, JsValue> {
        // rewrite any Error into JsValue
        match new_inner(hc_public_key_string, email, password) {
            Ok(v) => Ok(Self(v)),
            Err(e) => Err(e.to_string().into()),
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
            Err(_) => {
                return Err("Malformed signing payload, check docs for details."
                    .to_string()
                    .into())
            }
        };

        let signature = self.0.sign(&payload_vec);
        Ok(base64::encode_config(
            &signature.to_bytes()[..],
            base64::STANDARD_NO_PAD,
        ))
    }
}

fn new_inner(
    hc_public_key_string: String,
    email: String,
    password: String,
) -> Result<Keypair, Error> {
    let hc_public_key_bytes = base36::decode(&hc_public_key_string)?;
    let hc_public_key = PublicKey::from_bytes(&hc_public_key_bytes)?;
    Ok(admin_keypair_from(hc_public_key, &email, &password)?)
}

fn parse_payload(payload: &JsValue) -> Result<Vec<u8>, Error> {
    let payload_struct: Payload = payload.into_serde()?;
    match serde_json::to_vec(&payload_struct) {
        Ok(v) => Ok(v),
        Err(e) => Err(err_msg(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    const HC_PUBLIC_KEY: &str = "3llrdmlase6xwo9drzs6qpze40hgaucyf7g8xpjze6dz32s957";
    const EMAIL: &str = "pj@abba.pl";
    const PASSWORD: &str = "abba";
    const EXPECTED_SIGNATURE: &str =
        "viqqtbfbhTtAarkJjzOgO4cu4MFgGnshYHMjV3nITem01js9lTq0bG2Hwn9rXJi6xYVqOnq2NcosEMcRZ1CAAA";
    const WRONG_SIGNATURE: &str =
        "dQlFxqMQh0idWk6anOerf7b9/XssKkvSrVIv9gMuf7M31ivli6BM2ktCsv9FHB/2FfdwO4LS8muOkFjSt7uAAg";
    const EXPECTED_KEYPAIR_BYTES: [u8; 64] = [
        82, 253, 185, 87, 98, 217, 46, 233, 252, 159,
        103, 182, 121, 229, 22, 25, 34, 216, 81, 60,
        31, 204, 200, 63, 63, 233, 220, 47, 221, 74,
        86, 129, 103, 252, 79, 147, 189, 195, 172, 28,
        182, 243, 169, 66, 16, 196, 175, 183, 244, 207,
        211, 230, 5, 171, 105, 190, 23, 195, 137, 80,
        99, 254, 9, 250,
    ];

    impl HpAdminKeypair {
        pub fn to_bytes(&self) -> [u8; 64] {
            self.0.to_bytes()
        }
    }

    #[test]
    fn create_correct_keypair() {
        let my_keypair = HpAdminKeypair::new(
            HC_PUBLIC_KEY.to_string(),
            EMAIL.to_string(),
            PASSWORD.to_string(),
        )
        .unwrap();
        let my_keypair_bytes = my_keypair.to_bytes();

        assert_eq!(my_keypair_bytes[..], EXPECTED_KEYPAIR_BYTES[..]);
    }

    #[test]
    fn test_base36_decode() {
        assert_eq!(
            base36::decode("fg3h7vpw7een6jwwnzmq").unwrap(),
            b"Hello, World!"
        );
    }

    #[test]
    fn test_base36_encode() {
        assert_eq!(base36::encode(b"Hello, World!"), "fg3h7vpw7een6jwwnzmq");
    }

    #[wasm_bindgen_test]
    fn create_correct_signature() {
        let payload = Payload {
            method: "get".to_string(),
            uri: "/someuri".to_string(),
            body_string: "".to_string(),
        };

        let payload_js = JsValue::from_serde(&payload).unwrap();
        let my_keypair = HpAdminKeypair::new(
            HC_PUBLIC_KEY.to_string(),
            EMAIL.to_string(),
            PASSWORD.to_string(),
        )
        .unwrap();
        let signature = my_keypair.sign(&payload_js).unwrap();

        assert_eq!(signature, EXPECTED_SIGNATURE);
    }

    #[wasm_bindgen_test]
    fn create_incorrect_signature() {
        let payload = Payload {
            method: "get".to_string(),
            uri: "/someuri".to_string(),
            body_string: "".to_string(),
        };
        let payload_js = JsValue::from_serde(&payload).unwrap();
        let my_keypair = HpAdminKeypair::new(
            HC_PUBLIC_KEY.to_string(),
            EMAIL.to_string(),
            PASSWORD.to_string(),
        )
        .unwrap();
        let signature = my_keypair.sign(&payload_js).unwrap();

        assert_ne!(signature, WRONG_SIGNATURE);
    }
}
