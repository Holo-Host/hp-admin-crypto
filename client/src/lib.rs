pub mod util;

use crate::util::*;
use ed25519_dalek::Signer;
use ed25519_dalek::{Keypair, PublicKey};
use hpos_config_core::admin_keypair_from;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct HpAdminKeypair(Keypair);

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

    /// @description Sign string and return base64 encoded signature.
    /// @example
    /// myKeys = new HpAdminKeypair( hc_public_key_string, email, password );
    /// const payload = "Some auth token";
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
    let payload_string: String = payload.into_serde().map_err(into_js_error)?;
    Ok(serde_json::to_vec(&payload_string).map_err(into_js_error)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    const HC_PUBLIC_KEY: &str = "5m5srup6m3b2iilrsqmxu6ydp8p8cr0rdbh4wamupk3s4sxqr5";
    const EMAIL: &str = "pj@abba.pl";
    const PASSWORD: &str = "abbaabba";

    impl HpAdminKeypair {
        pub fn to_bytes(&self) -> [u8; 64] {
            self.0.to_bytes()
        }
    }

    #[test]
    fn create_correct_keypair() {
        let expected_hp_admin_pubkey: &str = "FBtaf29RmsFketdMt8LoI2RCwhDKj6PSAOQhe3A/3Bw";

        let admin_keypair = HpAdminKeypair::new(
            HC_PUBLIC_KEY.to_string(),
            EMAIL.to_string(),
            PASSWORD.to_string(),
        )
        .unwrap();

        let hp_admin_pubkey = base64::encode_config(
            &admin_keypair.0.public.to_bytes()[..],
            base64::STANDARD_NO_PAD,
        );

        assert_eq!(hp_admin_pubkey, expected_hp_admin_pubkey);
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
        let expected_signature =
            "kRBI5Yon9Sxcvt8TXJI3Hbb9bHUe9UcWUy64jTky34v2DEauF5UDFvmk7tGJm9RY5xLrRrobeSe1HimPbFRrBg";

        let payload = "Some auth token";

        let payload_js = JsValue::from_str(&payload);
        let my_keypair = HpAdminKeypair::new(
            HC_PUBLIC_KEY.to_string(),
            EMAIL.to_string(),
            PASSWORD.to_string(),
        )
        .unwrap();
        let signature = my_keypair.sign(&payload_js).unwrap();

        assert_eq!(signature, expected_signature);
    }
}
