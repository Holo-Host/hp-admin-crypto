extern crate hyper;

use futures::{
    future::{self, Either},
    Future, Stream,
};
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::{service, Body, Request, Response, Server, StatusCode};

use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::Mutex;
use std::{env, fs};

use ed25519_dalek::{PublicKey, Signature, Keypair};
use hpos_config_core::config::{admin_keypair_from, Config};

use log::{debug, error, info};

lazy_static! {
    static ref X_HPOS_ADMIN_SIGNATURE: HeaderName =
        HeaderName::from_lowercase(b"x-hpos-admin-signature").unwrap();
    static ref X_ORIGINAL_URI: HeaderName = HeaderName::from_lowercase(b"x-original-uri").unwrap();
    static ref HP_PUBLIC_KEY: Mutex<Option<PublicKey>> = Mutex::new(None);
}

#[derive(Serialize, Deserialize, Debug)]
struct Payload {
    method: String,
    request: String,
    body: String,
}

// Create response based on the request parameters
fn create_response(req: Request<Body>) -> impl Future<Item = Response<Body>, Error = hyper::Error> {
    let (parts, body) = req.into_parts();

    match parts.uri.path() {
        "/" => {
            let entire_body = body.concat2();
            let res = entire_body.map(|body| {
                // Extract X-Original-URI header value, 401 when problems occur
                let req_uri_str = match parts.headers.get(&*X_ORIGINAL_URI) {
                    Some(s) => s.to_str(),
                    None => {
                        debug!("Received request with no \"X-Original-URI\" header.");
                        return respond_success(false);
                    }
                };

                let req_uri_string = match req_uri_str {
                    Ok(s) => s.to_string(),
                    _ => {
                        debug!("Could not parse \"X-Original-URI\" header value.");
                        return respond_success(false);
                    }
                };

                debug!(
                    "Processing signature verification request for URI {}",
                    req_uri_string
                );

                let body = match String::from_utf8(body.to_vec()) {
                    Ok(s) => s,
                    Err(e) => {
                        debug!("Error parsing request body: {}", e);
                        return respond_success(false);
                    }
                };

                let payload = Payload {
                    method: parts.method.to_string().to_ascii_lowercase(),
                    request: req_uri_string,
                    body: body,
                };

                let public_key = match read_hp_pubkey() {
                    Ok(pk) => pk,
                    Err(e) => {
                        debug!("{}", e);
                        return respond_success(false);
                    }
                };

                let is_verified = match verify_request(payload, parts.headers, public_key) {
                    Ok(b) => b,
                    Err(e) => {
                        debug!("Error while verifying signature: {}", e);
                        return respond_success(false);
                    }
                };

                respond_success(is_verified)
            });

            Either::A(res)
        }
        _ => {
            let res = future::ok(respond_success(false));
            Either::B(res)
        }
    }
}

fn verify_request(
    payload: Payload,
    headers: HeaderMap<HeaderValue>,
    public_key: PublicKey,
) -> Result<bool, Box<dyn Error>> {
    let payload_vec = serde_json::to_vec(&payload)?;

    if let Some(signature_base64) = headers.get(&*X_HPOS_ADMIN_SIGNATURE) {
        if let Ok(signature_vec) = base64::decode_config(&signature_base64, base64::STANDARD_NO_PAD)
        {
            if let Ok(signature_bytes) = Signature::from_bytes(&signature_vec) {
                if public_key.verify(&payload_vec, &signature_bytes).is_ok() {
                    debug!("Signature verified successfully");
                    return Ok(true);
                }
            }
        }
    }

    debug!("Signature verified unsuccessfully");
    return Ok(false);
}

fn respond_success(is_verified: bool) -> hyper::Response<Body> {
    // construct response based on verification status
    match is_verified {
        true => Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap(),
        _ => Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::empty())
            .unwrap(),
    }
}

fn read_hp_pubkey() -> Result<PublicKey, Box<dyn Error>> {
    // Read cached value from HP_PUBLIC_KEY
    if let Some(pub_key) = *HP_PUBLIC_KEY.lock()? {
        debug!("Returning HP_PUBLIC_KEY from cache");
        return Ok(pub_key);
    }

    info!("Reading HP Admin Public Key from file.");

    let hpos_config_path = match env::var("HPOS_CONFIG_PATH") {
        Ok(s) => s,
        Err(e) => {
            error!("HPOS_CONFIG_PATH: {}", e);
            return Err("Can't read HP Admin PublicKey from file.")?;
        }
    };

    // Read from path
    let contents = match fs::read(&hpos_config_path) {
        Ok(s) => s,
        Err(e) => {
            error!("Error reading file {}: {}", &hpos_config_path, e);
            return Err("Can't read HP Admin PublicKey from file.")?;
        }
    };

    // Parse content
    let hpos_config: Config = match serde_json::from_slice(&contents) {
        Ok(s) => s,
        Err(e) => {
            error!("Error reading HP Admin Public Key from file: {}", e);
            return Err("Can't read HP Admin PublicKey from file.")?;
        }
    };

    // Update cached value in HP_PUBLIC_KEY
    let pub_key = hpos_config.admin_public_key();
    *HP_PUBLIC_KEY.lock()? = Some(pub_key);

    Ok(pub_key)
}

fn main() {
    env_logger::init();

    // Listen on http socket port 2884 - "auth" in phonespell
    let listen_address = ([127, 0, 0, 1], 2884).into();

    // Create a `Service` from servicing function
    let new_svc = || service::service_fn(create_response);

    let server = Server::bind(&listen_address).serve(new_svc).map_err(|e| {
        error!("server error: {}", e);
    });

    info!("Listening on http://{}", listen_address);

    // Run forever
    hyper::rt::run(server);
}

#[cfg(test)]
mod tests {
    use super::*;
    use base36;

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

    #[test]
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

        assert_eq!(verify_request(payload, headers, read_hp_pubkey().unwrap()).unwrap(), true)
    }

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

        assert_eq!(verify_request(payload, headers, admin_keypair.public).unwrap(), false)
    }
}
