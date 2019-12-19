pub mod util;

use crate::util::*;
use ed25519_dalek::{Keypair, PublicKey};
use hpos_config_core::admin_keypair_from;
use serde::*;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct HpAdminKeypair(Keypair);

#[derive(Serialize, Deserialize, Debug)]
struct Payload {
    method: String,
    request: String,
    body: String,
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
    ) -> Fallible<HpAdminKeypair> {
        console_error_panic_hook::set_once();
        let keypair = new_inner(hc_public_key_string, email, password)?;
        Ok(Self(keypair))
    }

    /// @description Sign payload and return base64 encoded signature.
    /// Requires properly formatted payload:
    /// const payload = {
    ///     method: String,
    ///     request: String,
    ///     body: String
    /// }
    /// @example
    /// myKeys = new HpAdminKeypair( hc_public_key_string, email, password );
    /// const payload = {
    ///     method: "get",
    ///     request: "/someuri",
    ///     body: ""
    /// }
    /// myKeys.sign( payload );
    #[wasm_bindgen]
    pub fn sign(&self, payload: &JsValue) -> Fallible<String> {
        // return meaningful error message via JsValue
        let payload_vec = parse_payload(payload)?;
        let signature = self.0.sign(&payload_vec);
        Ok(base64::encode_config(
            &signature.to_bytes()[..],
            base64::STANDARD_NO_PAD,
        ))
    }
}

fn new_inner(hc_public_key_string: String, email: String, password: String) -> Fallible<Keypair> {
    let hc_public_key_bytes =
        base36::decode(&hc_public_key_string).map_err(|e| JsValue::from(e.to_string()))?;
    let hc_public_key = PublicKey::from_bytes(&hc_public_key_bytes).map_err(into_js_error)?;
    let keypair = admin_keypair_from(hc_public_key, &email, &password)
        .map_err(|e| into_js_error(e.compat()))?;
    Ok(keypair)
}

fn parse_payload(payload: &JsValue) -> Fallible<Vec<u8>> {
    let payload_struct: Payload = payload.into_serde().map_err(into_js_error)?;
    Ok(serde_json::to_vec(&payload_struct).map_err(into_js_error)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    const HC_PUBLIC_KEY: &str = "3llrdmlase6xwo9drzs6qpze40hgaucyf7g8xpjze6dz32s957";
    const EMAIL: &str = "pj@abba.pl";
    const PASSWORD: &str = "abba";
    const EXPECTED_SIGNATURE: &str =
        "b1QKomb7z1/W6gb0bNwc85OhdZED71NFenkCg5xBFFwSYEFJnqo/jcNn3RZbPPJwTBSN5bTEt0jCI1wtvDTGCQ";
    const WRONG_SIGNATURE: &str =
        "dQlFxqMQh0idWk6anOerf7b9/XssKkvSrVIv9gMuf7M31ivli6BM2ktCsv9FHB/2FfdwO4LS8muOkFjSt7uAAg";
    const EXPECTED_KEYPAIR_BYTES: [u8; 64] = [
        82, 253, 185, 87, 98, 217, 46, 233, 252, 159, 103, 182, 121, 229, 22, 25, 34, 216, 81, 60,
        31, 204, 200, 63, 63, 233, 220, 47, 221, 74, 86, 129, 103, 252, 79, 147, 189, 195, 172, 28,
        182, 243, 169, 66, 16, 196, 175, 183, 244, 207, 211, 230, 5, 171, 105, 190, 23, 195, 137,
        80, 99, 254, 9, 250,
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
            request: "/someuri".to_string(),
            body: "".to_string(),
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
            request: "/someuri".to_string(),
            body: "".to_string(),
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

    #[wasm_bindgen_test]
    fn pass_incorrect_payload() {
        #[derive(Serialize, Deserialize, Debug)]
        struct PayloadErr {
            method: String,
            request: String,
        }
        let payload_err = PayloadErr {
            method: "get".to_string(),
            request: "/someuri".to_string(),
        };

        let payload_err_js = JsValue::from_serde(&payload_err).unwrap();
        let my_keypair = HpAdminKeypair::new(
            HC_PUBLIC_KEY.to_string(),
            EMAIL.to_string(),
            PASSWORD.to_string(),
        )
        .unwrap();
        let error = my_keypair.sign(&payload_err_js);

        assert!(error.is_err());
    }
}
