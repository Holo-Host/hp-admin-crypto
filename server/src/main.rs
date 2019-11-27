extern crate hyper;

use hyper::{service, Request, Response, Body, Server, StatusCode};
use futures::{future::{self, Either}, Future, Stream};

// Create response based on the request parameters
fn crete_response(req: Request<Body>) -> impl Future<Item = Response<Body>, Error = hyper::Error> {
    // Create payload
    let (parts, body) = req.into_parts();

    match parts.uri.path() {
        "/" => {
            let entire_body = body.concat2();
            let res = entire_body.map(|body| {
                let s = String::from_utf8(body.to_vec()).expect("Found invalid UTF-8");
                println!("{}",s);
                Response::new(Body::from("abba\n"))
            });

            println!("Method: {}\nUri: {}\n", parts.method, parts.uri);
            Either::A(res)
        }
        _ => {
            let body = Body::from("Please connect to /\n");
            let res = future::ok(Response::new(body));
            Either::B(res)
        }
    }
}

/*
// Verify signature
let verification = true;

// construct response based on verification and query params
match verification {
    true => {
        Response::new(Body::from("abba\n"))
    },
    _ => {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap()
    }
}
*/


/*
fn redirect_home() -> ResponseFuture {
    Box::new(future::ok(
        Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(header::LOCATION, "/")
            .body(Body::from("abba"))
            .unwrap(),
    ))
}*/

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
