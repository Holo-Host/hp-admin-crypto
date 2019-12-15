use failure::Error;
// use wasm_bindgen::prelude::*;

use ed25519_dalek::{Keypair, PublicKey};
use hpos_state_core::admin_keypair_from;


pub struct HpAdminKeypair(Keypair);

impl HpAdminKeypair {
    pub fn new(hc_public_key_string: String, email: String, password: String) -> Result<Self, Error> {
        // First base32 decode hc_public_key_string
        let hc_public_key_bytes = base36::decode(&hc_public_key_string)?;
        let hc_public_key = PublicKey::from_bytes(&hc_public_key_bytes)?;
        Ok(Self(admin_keypair_from(hc_public_key, &email, &password)?))
    }

    // Return base64 encoded signature of the payload
    pub fn sign(&self, payload: &[u8]) -> String {
        let signature = self.0.sign(payload);
        base64::encode_config(&signature.to_bytes()[..], base64::STANDARD_NO_PAD)
    }

}

// TODO: wasmify, convert to human readible errors for js user, check how do we handle errors in js

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_correct_signature() {
        let hc_public_key = "3llrdmlase6xwo9drzs6qpze40hgaucyf7g8xpjze6dz32s957".to_string();
        let email = "pj@abba.pl".to_string();
        let password = "abba".to_string();
        let payload = &[5, 252, 45, 63, 144, 186, 182, 222, 182, 219, 150, 253, 76, 240, 136];
        let expected_signature = "adx7M5oKbrpFIQj36VIPsPyplPE+KtJ1E0u4b2IH+yZGnoFep2U8djNNgz5CMcs6bZ3V2dKQNMrN2c6TGxIQBQ";

        let my_keypair = HpAdminKeypair::new(hc_public_key, email, password).unwrap();
        let signature = my_keypair.sign(payload);

        assert_eq!(signature, expected_signature);
    }

    #[test]
    fn create_incorrect_signature() {
        let hc_public_key = "3llrdmlase6xwo9drzs6qpze40hgaucyf7g8xpjze6dz32s957".to_string();
        let email = "pj@abba.pl".to_string();
        let password = "abba".to_string();
        let payload = &[5, 252, 45, 63, 144, 186, 182, 222, 182, 219, 150, 253, 76, 240, 136];
        let wrong_signature = "dQlFxqMQh0idWk6anOerf7b9/XssKkvSrVIv9gMuf7M31ivli6BM2ktCsv9FHB/2FfdwO4LS8muOkFjSt7uAAg";

        let my_keypair = HpAdminKeypair::new(hc_public_key, email, password).unwrap();
        let signature = my_keypair.sign(payload);
        println!("{:?}", signature);

        assert_ne!(signature, wrong_signature);
    }
}






/*
// https://github.com/rustwasm/wasm-bindgen/issues/1004
fn state_raw(email: String, password: String) -> Result<JsValue, Error> {
    let (state, public_key) = State::new(email, password, None)?;

    let state_data = StateData {
        state: serde_json::to_string_pretty(&state)?,
        url: public_key::to_url(&public_key)?.into_string(),
    };

    Ok(JsValue::from_serde(&state_data)?)
}

#[wasm_bindgen]
pub fn state(email: String, password: String) -> Result<JsValue, JsValue> {
    match state_raw(email, password) {
        Ok(js_val) => Ok(js_val),
        Err(e) => Err(e.to_string().into()),
    }
}
*/