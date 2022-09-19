use dbw::{bfromcstr, dbw_connect, DBWDBType, DBWDBType_DBW_SQLITE3};
#[allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server};
use std::convert::Infallible;
use std::ffi::CStr;
use std::ffi::CString;
use std::net::SocketAddr;
use std::ptr::{null_mut, null};
use std::str;

async fn hello_world(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    let mut response = Response::new(Body::empty());
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => {
            *response.body_mut() = Body::from("{\"status\": \"ok\"}");
        }
        _ => {
            *response.body_mut() = Body::from("{\"status\": \"ok\"}");
        }
    }
    Ok(response)
}

#[tokio::main]
async fn main() {
    unsafe {
        let h = dbw_connect(
            DBWDBType_DBW_SQLITE3,
            bfromcstr(CStr::from_bytes_with_nul(b"test\0").unwrap().as_ptr()),
            null_mut(),
        );
        assert!(!std::ptr::eq(h, null()));
    }
    // We'll bind to 127.0.0.1:3000
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    // A `Service` is needed for every connection, so this
    // creates one from our `hello_world` function.
    let make_svc = make_service_fn(|_conn| async {
        // service_fn converts our function into a `Service`
        Ok::<_, Infallible>(service_fn(hello_world))
    });

    let server = Server::bind(&addr).serve(make_svc);

    // Run this server for... forever!
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}
