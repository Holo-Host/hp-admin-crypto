extern crate hyper;

use futures::{
    future::{self, Either},
    Future, Stream,
};
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::{service, Body, Request, Response, Server, StatusCode, Uri};

use ed25519_dalek::ed25519::Signature;
use ed25519_dalek::PublicKey;
use ed25519_dalek::Verifier;
use hpos_config_core::config::Config;

use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::Mutex;
use std::{env, fs};
use url::form_urlencoded;

use log::{debug, error, info};

lazy_static! {
    static ref X_HPOS_ADMIN_SIGNATURE: HeaderName =
        HeaderName::from_lowercase(b"x-hpos-admin-signature").unwrap();
    static ref X_ORIGINAL_URI: HeaderName = HeaderName::from_lowercase(b"x-original-uri").unwrap();
    static ref X_ORIGINAL_METHOD: HeaderName =
        HeaderName::from_lowercase(b"x-original-method").unwrap();
    static ref X_ORIGINAL_BODY: HeaderName = HeaderName::from_lowercase(b"x-body-hash").unwrap();
    static ref HP_PUBLIC_KEY: Mutex<Option<PublicKey>> = Mutex::new(None);
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Payload {
    method: String,
    request: String,
    body: String,
}

// Create response based on the request parameters
fn create_response(req: Request<Body>) -> impl Future<Item = Response<Body>, Error = hyper::Error> {
    let (parts, body) = req.into_parts();

    match parts.uri.path() {
        "/auth/" => {
            let entire_body = body.concat2();

            let res = entire_body.map(|_| {
                if let Ok(public_key) = read_hp_pubkey() {
                    if let Ok(payload) = create_payload(&parts.headers) {
                        if let Ok(signature) = signature_from_headers(parts.headers) {
                            if let Ok(is_verified) = verify_request(payload, signature, public_key)
                            {
                                return respond_success(is_verified);
                            }
                        }
                    }
                }

                respond_success(false)
            });

            Either::A(res)
        }
        _ => {
            let res = future::ok(respond_success(false));
            Either::B(res)
        }
    }
}

fn uri_from_headers(headers: &HeaderMap<HeaderValue>) -> Option<Uri> {
    if let Some(result) = headers.get(&*X_ORIGINAL_URI) {
        if let Ok(uri_str) = result.to_str() {
            let uri = Uri::builder()
                .scheme("https")
                .authority("abba.pl")
                .path_and_query(uri_str)
                .build()
                .unwrap();

            return Some(uri);
        }
    }

    return None;
}

fn path_from_headers(headers: &HeaderMap<HeaderValue>) -> Result<String, Box<dyn Error>> {
    if let Some(uri) = uri_from_headers(headers) {
        return Ok(uri.path().to_string());
    }

    debug!("Received request with no path in \"X-Original-URI\" header.");
    return Err("")?;
}

fn method_from_headers(headers: &HeaderMap<HeaderValue>) -> Result<String, Box<dyn Error>> {
    match headers.get(&*X_ORIGINAL_METHOD) {
        Some(s) => return Ok(s.to_str()?.to_string().to_ascii_lowercase()),
        None => {
            debug!("Received request with no \"X-Original-Method\" header.");
            return Err("")?;
        }
    };
}

fn body_from_headers(headers: &HeaderMap<HeaderValue>) -> Result<String, Box<dyn Error>> {
    match headers.get(&*X_ORIGINAL_BODY) {
        Some(s) => return Ok(s.to_str()?.to_string()),
        None => {
            debug!("Received request with no \"X-Body-Hash\" header, using empty body.");
            return Ok("".to_string());
        }
    };
}

fn create_payload(headers: &HeaderMap<HeaderValue>) -> Result<Payload, Box<dyn Error>> {
    Ok(Payload {
        method: method_from_headers(headers)?,
        request: path_from_headers(headers)?,
        body: body_from_headers(headers)?,
    })
}

fn signature_from_headers(headers: HeaderMap<HeaderValue>) -> Result<Signature, Box<dyn Error>> {
    if let Some(signature_base64) = extract_base64_signature(headers) {
        debug!("Received signature '{}'", signature_base64);
        return parse_signature(signature_base64);
    }

    debug!("Received request with no signature");
    Err("No signature 'X-Hpos-Admin-Signature' found in headers nor query string")?
}

fn extract_base64_signature(headers: HeaderMap<HeaderValue>) -> Option<String> {
    if let Some(value) = headers.get(&*X_HPOS_ADMIN_SIGNATURE) {
        if let Ok(value_str) = value.to_str() {
            return Some(value_str.to_string());
        }
    }

    if let Some(uri) = uri_from_headers(&headers) {
        if let Some(query_str) = uri.query() {
            let args = form_urlencoded::parse(query_str.as_bytes()).into_owned();

            for arg in args {
                let (key, value) = arg;
                if key.to_ascii_lowercase() == "x-hpos-admin-signature".to_string() {
                    return Some(value);
                }
            }
        }
    }

    None
}

fn parse_signature(signature_base64: String) -> Result<Signature, Box<dyn Error>> {
    if let Ok(signature_vec) = base64::decode_config(&signature_base64, base64::STANDARD_NO_PAD) {
        if let Ok(signature) = Signature::from_bytes(&signature_vec) {
            return Ok(signature);
        }
    };

    Err("Signature is not parsable")?
}

fn verify_request(
    payload: Payload,
    signature: Signature,
    public_key: PublicKey,
) -> Result<bool, Box<dyn Error>> {
    debug!(
        "Processing signature verification request for Method: {}, request: {}, body: {}",
        payload.method, payload.request, payload.body
    );

    let payload_vec = serde_json::to_vec(&payload)?;

    if public_key.verify(&payload_vec, &signature).is_ok() {
        debug!("Signature verification passed");
        return Ok(true);
    }

    debug!("Signature verification failed");
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
mod tests;
