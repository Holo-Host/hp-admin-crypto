use failure::Error;
// use wasm_bindgen::prelude::*;

use ed25519_dalek::{Keypair, PublicKey};
use hpos_state_core::admin_keypair_from;

#[derive(Debug)]
pub struct HpAdminKeypair(Keypair);

impl HpAdminKeypair {
    pub fn new(hc_public_key_string: String, email: String, password: String) -> Result<Self, Error> {
        let hc_public_key_bytes = base36::decode(&hc_public_key_string)?;
        let hc_public_key = PublicKey::from_bytes(&hc_public_key_bytes)?;
        Ok(Self(admin_keypair_from(hc_public_key, &email, &password)?))
    }

    // Returns base64 encoded signature of the payload
    pub fn sign(&self, payload: &[u8]) -> String {
        let signature = self.0.sign(payload);
        base64::encode_config(&signature.to_bytes()[..], base64::STANDARD_NO_PAD)
    }
}

// TODO: wasmify, convert to human readible errors for js user, check how do we handle errors in js

#[cfg(test)]
mod tests {
    use super::*;

    const HC_PUBLIC_KEY: &str = "3llrdmlase6xwo9drzs6qpze40hgaucyf7g8xpjze6dz32s957";
    const EMAIL: &str = "pj@abba.pl";
    const PASSWORD: &str = "abba";
    const PAYLOAD: &[u8] = &[5, 252, 45, 63, 144, 186, 182, 222, 182, 219, 150, 253, 76, 240, 136];
    const EXPECTED_SIGNATURE: &str = "adx7M5oKbrpFIQj36VIPsPyplPE+KtJ1E0u4b2IH+yZGnoFep2U8djNNgz5CMcs6bZ3V2dKQNMrN2c6TGxIQBQ";
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
        let my_keypair = HpAdminKeypair::new(HC_PUBLIC_KEY.to_string(), EMAIL.to_string(), PASSWORD.to_string()).unwrap();
        let signature = my_keypair.sign(PAYLOAD);

        assert_eq!(signature, EXPECTED_SIGNATURE);
    }

    #[test]
    fn create_incorrect_signature() {
        let my_keypair = HpAdminKeypair::new(HC_PUBLIC_KEY.to_string(), EMAIL.to_string(), PASSWORD.to_string()).unwrap();
        let signature = my_keypair.sign(PAYLOAD);

        assert_ne!(signature, WRONG_SIGNATURE);
    }
}
