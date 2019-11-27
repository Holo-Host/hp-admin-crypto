extern crate hyper;

use hyper::{service, Request, Response, Body, Server, StatusCode};
use hyper::header::{HeaderMap, HeaderValue};
use futures::{future::{self, Either}, Future, Stream};
use serde_json::json;

// Create response based on the request parameters
fn crete_response(req: Request<Body>) -> impl Future<Item = Response<Body>, Error = hyper::Error> {
    let (parts, body) = req.into_parts();

    // TODO: pass into create_payload value of Header "X-Forwarded-For" as an uri rather than parts.uri
    // TODO: Make sure that payload passed to verification matches that from the frontend

    match parts.uri.path() {
        "/" => {
            let entire_body = body.concat2();
            let res = entire_body.map(move |body| {
                let body_string = String::from_utf8(body.to_vec()).expect("Found invalid UTF-8");
                let payload = create_payload(parts.method.to_string(), parts.uri.to_string(), body_string);
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
    println!("Payload: {}", payload);
    for (key, value) in headers.iter() {
        println!("Header: {:?}: {:?}", key, value);
    }
    true
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
