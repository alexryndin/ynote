use dbw::{
    bdestroy, bfromcstr, bstring, dbw_connect, dbw_get_snippet, DBWDBType, DBWDBType_DBW_SQLITE3,
    DBWError, DBWError_DBW_ERR_NOT_FOUND, DBWError_DBW_OK, DBWHandler,
};
use hyper::http::{Request, Response, StatusCode};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Server};
use serde_json::{Error, Value};
use std::convert::Infallible;
use std::error;
use std::ffi::CStr;
use std::ffi::CString;
use std::fmt;
use std::net::SocketAddr;
use std::ptr::{null, null_mut};
use std::str;
use std::sync::{Arc, Mutex};
use url;

struct YNote {
    dbh: SendPtr<*mut DBWHandler>,
}

unsafe impl<T> Send for SendPtr<T> {}
unsafe impl<T> Sync for SendPtr<T> {}

struct Bstring(bstring);
impl Drop for Bstring {
    fn drop(&mut self) {
        unsafe {
            bdestroy(self.0);
        }
    }
}

struct SendPtr<T>(T);

#[derive(Debug)]
struct YNoteError {
    kind: YNoteErrorKind,
    msg: String,
}

#[derive(Debug)]
enum YNoteErrorKind {
    ServerError,
    BadRequest,
    NotFound,
}

impl fmt::Display for YNoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)
    }
}

impl fmt::Display for YNoteErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl error::Error for YNoteError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(&self.kind)
    }
}

impl error::Error for YNoteErrorKind {}

async fn get_snippet_handler(
    req: Request<Body>,
    app: Arc<YNote>,
) -> Result<Response<Body>, hyper::Error> {
    let mut response = Response::new(Body::empty());
    let mut err: DBWError = 0;
    let mut params = url::form_urlencoded::parse(&req.uri().query().unwrap_or_default().as_bytes());
    //   let params = &req.uri().query();
    // let params = url::Url::parse(&req.uri().to_string()).unwrap().query_pairs();
    let id = params.find(|x| x.0 == "id");
    match id {
        None => {
            *response.status_mut() = StatusCode::BAD_REQUEST;
            *response.body_mut() = Body::from(r#"{"status": "error", "msg": "id required"}"#);
            return Ok(response);
        }
        Some(id) => {
            let id = id.1.parse::<i64>();
            match id {
                Err(_) => {
                    *response.status_mut() = StatusCode::BAD_REQUEST;
                    *response.body_mut() =
                        Body::from(r#"{"status": "error", "msg": "Couldn't parse id"}"#);
                    return Ok(response);
                }
                Ok(id) => unsafe {
                    let snippet = dbw_get_snippet(app.dbh.0, id, &mut err);
                    match err {
                        DBWError_DBW_OK => {
                            let snippet = CStr::from_ptr((*snippet).data.cast()).to_str().unwrap();
                            *response.body_mut() = Body::from(snippet);
                            return Ok(response);
                        }
                        DBWError_DBW_ERR_NOT_FOUND => {
                            *response.status_mut() = StatusCode::NOT_FOUND;
                            *response.body_mut() =
                                Body::from(r#"{"status": "error", "msg": "Couldn't parse id"}"#);
                            return Ok(response);
                        }
                        _ => {
                            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                            *response.body_mut() =
                                Body::from(r#"{"status": "error", "msg": "internal error"}"#);
                            return Ok(response);
                        }
                    }
                },
            }
        }
    }
}

async fn handler(req: Request<Body>, app: Arc<YNote>) -> Result<Response<Body>, hyper::Error> {
    let mut response = Response::new(Body::empty());
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => {
            *response.body_mut() = Body::from(r#"{"status": "ook"}"#);
        }
        (&Method::GET, "/api/get_snippet") => {return get_snippet_handler(req, app).await;},
        (&Method::POST, "/api/create_snippet") => {
            println!("{}", "jopa");
            let full_body = hyper::body::to_bytes(req.into_body()).await?;
            let v: Result<Value, serde_json::Error> = serde_json::from_str(
                &String::from_utf8_lossy(&full_body.iter().cloned().collect::<Vec<u8>>()),
            );

            match v {
                Err(e) => {
                    *response.status_mut() = StatusCode::BAD_REQUEST;
                    *response.body_mut() =
                        Body::from(r#"{"status": "error", "msg": "wrong json"}"#);
                }
                Ok(v) => {
                    *response.body_mut() = Body::from(format!("{}", v["data"]));
                }
            }
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
        async move { Ok::<_, Infallible>(service_fn(move |req| handler(req, app.clone()))) }
    });

    Server::bind(&addr).serve(make_svc).await?;
    Ok(())

    // Run this server for... forever!
}
