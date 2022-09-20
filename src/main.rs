use dbw::{bfromcstr, dbw_connect, DBWDBType, DBWDBType_DBW_SQLITE3, DBWHandler};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server};
use std::convert::Infallible;
use std::ffi::CStr;
use std::ffi::CString;
use std::net::SocketAddr;
use std::ptr::{null, null_mut};
use std::str;
use std::sync::{Arc, Mutex};

struct YNote {
    dbh: SendPtr<*mut DBWHandler>,
}

unsafe impl Send for SendPtr<*mut DBWHandler> {}
unsafe impl Sync for SendPtr<*mut DBWHandler> {}

struct SendPtr<T>(T);

async fn hello_world(req: Request<Body>, app: Arc<YNote>) -> Result<Response<Body>, Infallible> {
    let mut response = Response::new(Body::empty());
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => {
            *response.body_mut() = Body::from(r#"{"status": "ok"}"#);
        }
        (&Method::GET, "/api/create_snippet") => {
            *response.body_mut() = Body::from(r#"{"status": "ok"}"#);
        }
        _ => {
            *response.body_mut() = Body::from(r#"{"status": "ok"}"#);
        }
    }
    Ok(response)
}

fn use_counter(counter: Arc<Mutex<u64>>) -> Response<Body> {
    let mut data = counter.lock().unwrap();
    *data += 1;
    Response::new(Body::from(format!("Counter: {}\n", data)))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = Arc::new(YNote {
        dbh: unsafe {
            let h = dbw_connect(
                DBWDBType_DBW_SQLITE3,
                bfromcstr(CStr::from_bytes_with_nul(b"test.db\0").unwrap().as_ptr()),
                null_mut(),
            );
            assert!(!std::ptr::eq(h, null()));
            SendPtr(h)
        },
    });
    // We'll bind to 127.0.0.1:3000
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    // A `Service` is needed for every connection, so this
    // creates one from our `hello_world` function.
    let make_svc = make_service_fn(move |conn| {
        // service_fn converts our function into a `Service`
        let app = app.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                hello_world(req, app.clone())
            }))
        }
    });

    Server::bind(&addr).serve(make_svc).await?;
    Ok(())

    // Run this server for... forever!
}
