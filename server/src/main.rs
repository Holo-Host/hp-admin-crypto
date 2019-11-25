extern crate hyper;

use hyper::service::service_fn_ok;
use hyper::{Request, Response, Body, Server};
use hyper::rt::Future;


// Create response based on the request parameters
fn crete_response(_request: Request<Body>) -> Response<Body> {
    Response::new(Body::from("Abba"))
}

fn main() {
    // Listen on http socket port 2884 - "auth" in phonespell
    let listen_address = ([127,0,0,1], 2884).into();

    // Create a `Service` from servicing function
    let new_svc = || {
        service_fn_ok(crete_response)
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
