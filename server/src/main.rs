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
use std::error::Error;
use std::sync::Mutex;
use std::time::{SystemTime, Duration};
use std::{env, fs};
use url::form_urlencoded;

use log::{debug, error, info};

lazy_static! {
    static ref X_HPOS_ADMIN_SIGNATURE: HeaderName =
        HeaderName::from_lowercase(b"x-hpos-admin-signature").unwrap();
    static ref X_ORIGINAL_URI: HeaderName = HeaderName::from_lowercase(b"x-original-uri").unwrap();
    static ref X_HPOS_AUTH_TOKEN: HeaderName =
        HeaderName::from_lowercase(b"x-hpos-auth-token").unwrap();
    static ref X_ORIGINAL_BODY: HeaderName = HeaderName::from_lowercase(b"x-body-hash").unwrap();
    static ref STORED_AUTH_TOKEN: Mutex<Option<AuthToken>> = Mutex::new(None);
}

const TOKEN_EXPIERY_DURATION: Duration = Duration::from_secs(60*60*24*30); // 30 days


struct AuthToken {
    value: String,
    created: SystemTime,
}

// Create response based on the request parameters
fn create_response(req: Request<Body>) -> impl Future<Item = Response<Body>, Error = hyper::Error> {
    let (parts, body) = req.into_parts();

    match parts.uri.path() {
        "/auth/" => {
            let entire_body = body.concat2();

            let res = entire_body.map(move |_| {
                if let Some(auth_token) = token_from_headers_or_query(&parts.headers) {
                    if let Some(signature) = signature_from_headers(&parts.headers) {
                        if let Ok(public_key) = read_hp_pubkey() {
                            if verify_signature(&auth_token, signature, public_key) {
                                if let Ok(_) = save_auth_token(auth_token) {
                                    debug!("Signature verified succesfully, saved new STORED_AUTH_TOKEN");
                                    return respond_success(true);
                                }
                            }
                        }
                    } else {
                        return respond_success(verify_token(&auth_token))
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

fn token_from_headers_or_query(headers: &HeaderMap<HeaderValue>) -> Option<String> {
    if let Some(value) = headers.get(&*X_HPOS_AUTH_TOKEN) {
        if let Ok(value_str) = value.to_str() {
            return Some(value_str.to_owned());
        }
    }

    if let Some(uri) = uri_from_headers(&headers) {
        if let Some(query_str) = uri.query() {
            let args = form_urlencoded::parse(query_str.as_bytes()).into_owned();

            for arg in args {
                let (key, value) = arg;
                if key.to_ascii_lowercase() == "x-hpos-auth-token".to_string() {
                    return Some(value);
                }
            }
        }
    }

    error!("Received request with no auth token in headers nor query string");
    None
}

fn signature_from_headers(headers: &HeaderMap<HeaderValue>) -> Option<Signature> {
    if let Some(value) = headers.get(&*X_HPOS_ADMIN_SIGNATURE) {
        if let Ok(signature_base64) = value.to_str() {
            debug!("Received signature '{}'", signature_base64);
            return parse_signature(signature_base64);
        }
    }

    debug!("Received request with no signature in headers nor query string");
    None
}

fn parse_signature(signature_base64: &str) -> Option<Signature> {
    if let Ok(signature_vec) = base64::decode_config(signature_base64, base64::STANDARD_NO_PAD) {
        if let Ok(signature) = Signature::from_bytes(&signature_vec) {
            return Some(signature);
        }
    };

    debug!("Signature is not parsable");
    None
}

fn verify_signature(token: &str, signature: Signature, public_key: PublicKey) -> bool {
    debug!(
        "Processing signature verification request for Auth Token: {}",
        token
    );

    if public_key.verify(token.as_bytes(), &signature).is_ok() {
        debug!("Signature verification passed");
        return true
    }

    debug!("Signature verification failed");
    false
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

    Ok(hpos_config.admin_public_key())
}

fn verify_token(received_token_value: &str) -> bool {
    // Read cached value from STORED_AUTH_TOKEN
    if let Ok(maybe_auth_token) = STORED_AUTH_TOKEN.lock() {
        if let Some(auth_token) = &*maybe_auth_token {
            debug!("Found STORED_AUTH_TOKEN in cache");
            // Check token expiery
            if let Ok(token_age) = auth_token.created.elapsed() {
                if token_age < TOKEN_EXPIERY_DURATION {
                    if auth_token.value == received_token_value {
                        // update token expiery in memory with current time
                        let _= save_auth_token(auth_token.value.clone());
                        debug!("received token matches STORED_AUTH_TOKEN");
                        return true;
                    }
                } else {
                    debug!("STORED_AUTH_TOKEN in cache expired");
                }
            }
        }
    }
    false
}

fn save_auth_token(value: String) -> Result<(), Box<dyn Error>> {
    *STORED_AUTH_TOKEN.lock()? = Some(AuthToken{
        value: value,
        created: SystemTime::now(),
    });
    Ok(())
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
