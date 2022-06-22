use super::*;
use base36;
use ed25519_dalek::Keypair;
use ed25519_dalek::Signer;
use hpos_config_core::config::admin_keypair_from;

const HC_PUBLIC_KEY: &str = "5m5srup6m3b2iilrsqmxu6ydp8p8cr0rdbh4wamupk3s4sxqr5";
const EMAIL: &str = "pj@abba.pl";
const PASSWORD: &str = "abbaabba";

#[test]
fn verify_hp_admin_match() {
    let expected_hp_admin_pubkey: &str = "FBtaf29RmsFketdMt8LoI2RCwhDKj6PSAOQhe3A/3Bw";

    let hc_public_key_bytes = base36::decode(HC_PUBLIC_KEY).unwrap();
    let hc_public_key = PublicKey::from_bytes(&hc_public_key_bytes).unwrap();

    let admin_keypair: Keypair = admin_keypair_from(hc_public_key, EMAIL, PASSWORD).unwrap();

    let hp_admin_pubkey = base64::encode_config(
        &admin_keypair.public.to_bytes()[..],
        base64::STANDARD_NO_PAD,
    );

    assert_eq!(hp_admin_pubkey, expected_hp_admin_pubkey);
}

#[test]
fn verify_signature_match_client() {
    let expected_signature: &str =
        "izQfuNi+RYNhuEN8qHCQUUOkT45V8I97uwmTGlLAuECROH8Lh0daCGdo4Nneg+BvUzmBgHHfF73HCTOPGXl7Dw";

    let hc_public_key_bytes = base36::decode(HC_PUBLIC_KEY).unwrap();
    let hc_public_key = PublicKey::from_bytes(&hc_public_key_bytes).unwrap();

    let admin_keypair: Keypair = admin_keypair_from(hc_public_key, EMAIL, PASSWORD).unwrap();

    // Now lets sign some payload
    let payload = Payload {
        method: "get".to_string(),
        request: "/api/v1/config".to_string(),
        body: "".to_string(),
    };

    let signature = admin_keypair.sign(&serde_json::to_vec(&payload).unwrap());
    let mut signature_base64 = String::new();
    base64::encode_config_buf(
        signature.to_bytes().as_ref(),
        base64::STANDARD_NO_PAD,
        &mut signature_base64,
    );

    assert_eq!(signature_base64, expected_signature);
}

/*#[test]
fn verify_request_smoke() {
    let hc_public_key_bytes = base36::decode(HC_PUBLIC_KEY).unwrap();
    let hc_public_key = PublicKey::from_bytes(&hc_public_key_bytes).unwrap();

    let admin_keypair: Keypair = admin_keypair_from(hc_public_key, EMAIL, PASSWORD).unwrap();

    // Now lets sign some payload
    let payload = Payload {
        method: "get".to_string(),
        request: "/api/v1/config".to_string(),
        body: "".to_string(),
    };

    let signature = admin_keypair.sign(&serde_json::to_vec(&payload).unwrap());
    let mut signature_base64 = String::new();
    base64::encode_config_buf(
        signature.to_bytes().as_ref(),
        base64::STANDARD_NO_PAD,
        &mut signature_base64,
    );

    let mut headers = HeaderMap::new();
    headers.insert("x-hpos-admin-signature", signature_base64.parse().unwrap());

    assert_eq!(
        verify_request(payload, headers, read_hp_pubkey().unwrap()).unwrap(),
        true
    )
}*/

#[test]
fn verify_request_fail() {
    let hc_public_key_bytes = base36::decode(HC_PUBLIC_KEY).unwrap();
    let hc_public_key = PublicKey::from_bytes(&hc_public_key_bytes).unwrap();

    let admin_keypair: Keypair = admin_keypair_from(hc_public_key, EMAIL, PASSWORD).unwrap();

    // Now lets sign some payload
    let payload = Payload {
        method: "get".to_string(),
        request: "/api/v1/config".to_string(),
        body: "".to_string(),
    };

    let signature = admin_keypair.sign(&serde_json::to_vec(&payload).unwrap());
    let mut signature_base64 = String::new();
    base64::encode_config_buf(
        signature.to_bytes().as_ref(),
        base64::STANDARD_NO_PAD,
        &mut signature_base64,
    );

    let mut headers = HeaderMap::new();
    headers.insert("x-hpos-admin-signature", "Wrong signature".parse().unwrap());

    assert_eq!(
        verify_request(payload, headers, admin_keypair.public).unwrap(),
        false
    )
}
