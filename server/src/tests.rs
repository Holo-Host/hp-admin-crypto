use super::*;
use base36;
use ed25519_dalek::{Keypair, Signer};
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
fn check_signature_matches_client() {
    // Signature created by client side
    let expected_signature: &str =
        "kRBI5Yon9Sxcvt8TXJI3Hbb9bHUe9UcWUy64jTky34v2DEauF5UDFvmk7tGJm9RY5xLrRrobeSe1HimPbFRrBg";

    let hc_public_key_bytes = base36::decode(HC_PUBLIC_KEY).unwrap();
    let hc_public_key = PublicKey::from_bytes(&hc_public_key_bytes).unwrap();

    let admin_keypair: Keypair = admin_keypair_from(hc_public_key, EMAIL, PASSWORD).unwrap();

    // Now lets sign a token
    let payload = "Some auth token";

    let signature = admin_keypair.sign(&serde_json::to_vec(&payload).unwrap());
    let mut signature_base64 = String::new();
    base64::encode_config_buf(
        signature.to_bytes().as_ref(),
        base64::STANDARD_NO_PAD,
        &mut signature_base64,
    );

    assert_eq!(signature_base64, expected_signature);
}

#[test]
fn extract_signature_from_headers() {
    let expected_signature: Option<Signature> = parse_signature("Right_signature");
    let mut headers = HeaderMap::new();
    headers.insert("x-hpos-admin-signature", "Right_signature".parse().unwrap());
    headers.insert(
        "x-original-uri",
        "/foo?x-hpos-admin-signature=Wrong_signature"
            .parse()
            .unwrap(),
    );

    assert_eq!(signature_from_headers(&headers), expected_signature);
}

#[test]
fn extract_token_from_headers() {
    let mut headers = HeaderMap::new();
    headers.insert("x-hpos-auth-token", "Right_token".parse().unwrap());
    headers.insert(
        "x-original-uri",
        "/foo?x-hpos-auth-token=Wrong_token".parse().unwrap(),
    );

    match token_from_headers_or_query(&headers) {
        Some(token) => assert_eq!(token, "Right_token"),
        None => panic!("Token extraction failed"),
    }
}

#[test]
fn extract_token_from_query() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-original-uri",
        "/foo?x-hpos-auth-token=Right_token".parse().unwrap(),
    );

    match token_from_headers_or_query(&headers) {
        Some(token) => assert_eq!(token, "Right_token"),
        None => panic!("Token extraction failed"),
    }
}

#[test]
fn verify_signature_of_token() {
    env_logger::init();

    let path = env::var("CARGO_MANIFEST_DIR").unwrap();
    let hpos_config_path = format!("{}/resources/test/hpos-config-v2.json", path);
    env::set_var("HPOS_CONFIG_PATH", &hpos_config_path);

    let auth_token_value = "Some auth token";
    let public_key = read_hp_pubkey().unwrap();
    debug!("Using pub key: {:?}", public_key);
    let signature = parse_signature("kRBI5Yon9Sxcvt8TXJI3Hbb9bHUe9UcWUy64jTky34v2DEauF5UDFvmk7tGJm9RY5xLrRrobeSe1HimPbFRrBg").unwrap();

    assert!(verify_signature(&auth_token_value, signature, public_key));
}

#[test]
fn verify_request_smoke() {
    env_logger::init();

    let path = env::var("CARGO_MANIFEST_DIR").unwrap();
    let hpos_config_path = format!("{}/resources/test/hpos-config-v2.json", path);
    env::set_var("HPOS_CONFIG_PATH", &hpos_config_path);

    // Create Hyper request with headers
    let request = Request::builder()
        .method("GET")
        .uri("https://localhost/")
        .header("X-Hpos-Auth-Token", "Some auth token")
        .header("x-hpos-admin-signature", "kRBI5Yon9Sxcvt8TXJI3Hbb9bHUe9UcWUy64jTky34v2DEauF5UDFvmk7tGJm9RY5xLrRrobeSe1HimPbFRrBg")
        .body(())
        .unwrap();

    let (parts, _) = request.into_parts();

    let response_code = create_response(&parts.headers).status();

    assert_eq!(response_code, StatusCode::OK)
}

// #[test]
// fn verify_request_fail() {
//     let hc_public_key_bytes = base36::decode(HC_PUBLIC_KEY).unwrap();
//     let hc_public_key = PublicKey::from_bytes(&hc_public_key_bytes).unwrap();

//     let admin_keypair: Keypair = admin_keypair_from(hc_public_key, EMAIL, PASSWORD).unwrap();

//     // Now lets sign some payload
//     let payload = Payload {
//         method: "get".to_string(),
//         request: "/api/v1/status".to_string(),
//         body: "".to_string(),
//     };

//     let wrong_payload = Payload {
//         method: "put".to_string(),
//         request: "/api/v1/config".to_string(),
//         body: "".to_string(),
//     };

//     let wrong_signature = admin_keypair.sign(&serde_json::to_vec(&wrong_payload).unwrap());
//     let mut signature_base64 = String::new();
//     base64::encode_config_buf(
//         wrong_signature.to_bytes().as_ref(),
//         base64::STANDARD_NO_PAD,
//         &mut signature_base64,
//     );

//     assert_eq!(
//         verify_request(payload, wrong_signature, admin_keypair.public).unwrap(),
//         false
//     )
// }
