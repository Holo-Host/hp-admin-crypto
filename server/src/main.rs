extern crate hyper;

use hyper::{service, Request, Response, Body, Server, StatusCode};
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use futures::{future::{self, Either}, Future, Stream};
use serde_json::json;
use lazy_static::lazy_static;
use ed25519_dalek::{PublicKey, PUBLIC_KEY_LENGTH, Signature};

lazy_static! {
    static ref X_HPOS_ADMIN_SIGNATURE: HeaderName = HeaderName::from_lowercase(b"x-hpos-admin-signature").unwrap();
    static ref X_FORWARDED_FOR: HeaderName = HeaderName::from_lowercase(b"x-forwarded-for").unwrap();
}

// Create response based on the request parameters
fn crete_response(req: Request<Body>) -> impl Future<Item = Response<Body>, Error = hyper::Error> {
    let (parts, body) = req.into_parts();

    match parts.uri.path() {
        "/" => {
            let entire_body = body.concat2();
            let res = entire_body.map(move |body| {
                // Extract X-Forwarded-For header value, panic for no header
                let req_uri = match parts.headers.get(&*X_FORWARDED_FOR) {
                    Some(s) => s.to_str().unwrap(),
                    None => panic!("Request does not contain \"X-Forwarded-For\" header."),
                };
                let body_string = String::from_utf8(body.to_vec()).expect("Found invalid UTF-8");
                let payload = create_payload(parts.method.to_string(), req_uri.to_string(), body_string);
                let is_verified = verify_request(payload, parts.headers);
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

fn create_payload (method: String, uri: String, body_string: String) -> String {
    let d = json!({
        "method": method,
        "uri": uri,
        "body": body_string
    }); 

    // Serialize it to a JSON string.
    serde_json::to_string(&d).unwrap()
}

fn verify_request(payload: String, headers: HeaderMap<HeaderValue>) -> bool {
    // Peek into vars
    println!("Payload: {}", payload);
    for (key, value) in headers.iter() {
        println!("Header: {:?}: {:?}", key, value);
    }

    // Retrieve X-Hpos-Admin-Signature
    let signature = match headers.get(&*X_HPOS_ADMIN_SIGNATURE) {
        Some(s) => s.to_str().unwrap(),
        None => return false,
    };

    println!("Signature: {}", signature);
    // Convert signature from base64 to Signature type and 401 on error
    // TODO: base64 decode signature first. Which lib? https://docs.rs/subtle-encoding/0.3.4/subtle_encoding/base64/index.html
    let signature_bytes = match Signature::from_bytes(&signature.as_bytes()) {
        Ok(s) => s,
        _ => return false,
    };

    // TODO: Retrieve Admin's signing key from HPOS
    let public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = [
   215,  90, 152,   1, 130, 177,  10, 183, 213,  75, 254, 211, 201, 100,   7,  58,
    14, 225, 114, 243, 218, 166,  35,  37, 175,   2,  26, 104, 247,   7,   81, 26];

    // Convert public key to PublicKey type, panic if not successful
    let public_key = PublicKey::from_bytes(&public_key_bytes).unwrap();

    // verify payload
    match public_key.verify(&payload.as_bytes(), &signature_bytes) {
        Ok(_) => return true,
        _ => return false
    }
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

fn main() {
    // Listen on http socket port 2884 - "auth" in phonespell
    let listen_address = ([127,0,0,1], 2884).into();

    // Create a `Service` from servicing function
    let new_svc = || {
        service::service_fn(crete_response)
    };

    let server = Server::bind(&listen_address)
        .serve(new_svc)
        .map_err(|e| {
            eprintln!("server error: {}", e);
        });

    println!("Listening on http://{}", listen_address);

    // Run forever
    hyper::rt::run(server);
}
