extern crate hyper;

use hyper::{service, Request, Response, Body, Server, StatusCode};
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use futures::{future::{self, Either}, Future, Stream};

use serde::{Serialize, Deserialize};
use lazy_static::lazy_static;
use std::{env, fs};
use std::error::Error;

use ed25519_dalek::{PublicKey, Signature};
use hpos_state_core::state::State;

use log::{info, debug, error};

lazy_static! {
    static ref X_HPOS_ADMIN_SIGNATURE: HeaderName = HeaderName::from_lowercase(b"x-hpos-admin-signature").unwrap();
    static ref X_ORIGINAL_URI: HeaderName = HeaderName::from_lowercase(b"x-original-uri").unwrap();
    static ref HP_PUBLIC_KEY: PublicKey = read_hp_pubkey();
}

#[derive(Serialize, Deserialize, Debug)]
struct Payload {
	method: String, 
	uri: String, 
	body_string: String
}

// Create response based on the request parameters
fn create_response(req: Request<Body>) -> impl Future<Item = Response<Body>, Error = hyper::Error> {
    let (parts, body) = req.into_parts();

    match parts.uri.path() {
        "/" => {
            let entire_body = body.concat2();
            let res = entire_body.map( |body| {
                // Extract X-Original-URI header value, panic for no header
                let req_uri_string = match parts.headers.get(&*X_ORIGINAL_URI) {
                    Some(s) => s.to_str().unwrap().to_string(),
                    None => {
						debug!("Received request with no \"X-Original-URI\" header.");
						return respond_success(false);
					},
                };
				debug!("Processing signature verification request for URI {}", req_uri_string);

                let body_string = match String::from_utf8(body.to_vec()) {
					Ok(s) => s,
					Err(e) => {
						debug!("Error parsing request body: {}", e);
						return respond_success(false);
					}
				};

				let payload = Payload {
					method: parts.method.to_string(), 
					uri: req_uri_string, 
					body_string: body_string
				};

                let is_verified = match verify_request(payload, parts.headers, &HP_PUBLIC_KEY) {
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

fn verify_request(payload: Payload, headers: HeaderMap<HeaderValue>, public_key: &PublicKey) -> Result<bool, Box<dyn Error>> {
	let payload_vec = serde_json::to_vec(&payload)?;
	
    if let Some(signature_base64) = headers.get(&*X_HPOS_ADMIN_SIGNATURE) {
        if let Ok(signature_vec) = base64::decode_config(&signature_base64, base64::STANDARD_NO_PAD) {
            if let Ok(signature_bytes) = Signature::from_bytes(&signature_vec) {
                if public_key.verify(&payload_vec, &signature_bytes).is_ok() {
					debug!("Signature verified successfully");
                    return Ok(true);
                }
            }
        }
    }

	debug!("Signature verified unsuccessfully");
    return Ok(false)
}

fn respond_success (is_verified: bool) -> hyper::Response<Body> {
    // construct response based on verification status
    match is_verified {
        true => {
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .unwrap()
        },
        _ => {
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::empty())
                .unwrap()
        }
    }
}

// TODO: rebuild to log errors and be triggered on each request and cache val if successful
fn read_hp_pubkey() -> PublicKey {
    let hpos_state_path = env::var("HPOS_STATE_PATH").expect("HPOS_STATE_PATH environmental variable is not present");

    info!("Reading HP Admin Public Key from {}.", hpos_state_path);

    // Read from path
    let contents = fs::read(hpos_state_path)
        .expect("Something went wrong reading HP Admin Public Key from file");

    // Parse content
    let hpos_state: State = serde_json::from_slice(&contents).unwrap();
    hpos_state.admin_public_key()
}

fn main() -> Result<(), Box<dyn Error>> {
	env_logger::init();

    // Listen on http socket port 2884 - "auth" in phonespell
    let listen_address = ([127,0,0,1], 2884).into();

    // Trigger lazy static to see if HP_PUBLIC_KEY assignment creates panic
    let _ = &*HP_PUBLIC_KEY;

    // Create a `Service` from servicing function
    let new_svc = || {
        service::service_fn(create_response)
    };

    let server = Server::bind(&listen_address)
        .serve(new_svc)
        .map_err(|e| {
            error!("server error: {}", e);
        });

    info!("Listening on http://{}", listen_address);

    // Run forever
    hyper::rt::run(server);

	Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{self, SECRET_KEY_LENGTH};
    use std::convert::From;

    #[test]
    fn verify_request_smoke() {
        // Get a legit request_hash signature, agent_id
        let secret: [u8; 32] = [0_u8; SECRET_KEY_LENGTH];
        let secret_key = ed25519_dalek::SecretKey::from_bytes(&secret).unwrap();
        let public_key = ed25519_dalek::PublicKey::from(&secret_key);
        let secret_key_exp = ed25519_dalek::ExpandedSecretKey::from(&secret_key);

        // Now lets sign some payload
		let payload = Payload {
			method: "get".to_string(), 
			uri: "/abba".to_string(), 
			body_string: "\"something\": \"interesting\"".to_string()
		};

        let signature = secret_key_exp.sign(&serde_json::to_vec(&payload).unwrap(), &public_key);
        let mut signature_base64 = String::new();
        base64::encode_config_buf(signature.to_bytes().as_ref(), base64::STANDARD_NO_PAD, &mut signature_base64);

        let mut headers = HeaderMap::new();
        headers.insert("x-hpos-admin-signature", signature_base64.parse().unwrap());

        assert_eq!(verify_request(payload, headers, &public_key), true)
    }
	
	#[test]
    fn verify_request_fail() {
        // Get a legit request_hash signature, agent_id
        let secret: [u8; 32] = [0_u8; SECRET_KEY_LENGTH];
        let secret_key = ed25519_dalek::SecretKey::from_bytes(&secret).unwrap();
        let public_key = ed25519_dalek::PublicKey::from(&secret_key);

        // Now lets sign some payload
		let payload = Payload {
			method: "get".to_string(), 
			uri: "/abba".to_string(), 
			body_string: "\"something\": \"interesting\"".to_string()
		};

        let mut headers = HeaderMap::new();
        headers.insert("x-hpos-admin-signature", "Wrong signature".parse().unwrap());

        assert_eq!(verify_request(payload, headers, &public_key), false)
    }
}
