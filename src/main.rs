use dbw::{
    bdestroy, bfromcstr, blk2bstr, bstring, dbw_connect, dbw_get_snippet, json_api_create_snippet,
    json_api_find_snippets, tagbstring, DBWDBType, DBWDBType_DBW_SQLITE3, DBWError,
    DBWError_DBW_ERR_ALREADY_EXISTS, DBWError_DBW_ERR_NOT_FOUND, DBWError_DBW_OK, DBWHandler,
};
use hyper::http::{Request, Response, StatusCode};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Server};
use serde::{Deserialize, Serialize};
use serde_json::{Error, Value};
use std::convert::Infallible;
use std::error;
use std::ffi::c_void;
use std::ffi::CStr;
use std::ffi::CString;
use std::fmt;
use std::net::SocketAddr;
use std::os::raw::{c_int, c_uchar};
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

#[derive(Serialize, Deserialize)]
struct CreateSnippet {
    title: String,
    content: String,
    r#type: String,
    tags: Vec<String>,
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

fn blk2tbstr(s: *mut c_uchar, l: c_int) -> tagbstring {
    tagbstring {
        data: s,
        slen: l,
        mlen: -1,
    }
}

async fn find_snippets_handler(
    req: Request<Body>,
    app: Arc<YNote>,
) -> Result<Response<Body>, hyper::Error> {
    let mut response = Response::new(Body::empty());

    let params = req.uri().query().unwrap_or_default();

    if params == "" {
        *response.status_mut() = StatusCode::NOT_FOUND;
        *response.body_mut() = Body::from(r#"{"status": "error", "msg": "query is missing"}"#);
        return Ok(response);
    }

    let params: Vec<(String, String)> = url::form_urlencoded::parse(&params.as_bytes())
        .into_owned()
        .collect();
    let tags = params
        .iter()
        .find(|x| x.0 == "tags")
        .map(|x| x.1.to_string());
    let title = params
        .iter()
        .find(|x| x.0 == "title")
        .map(|x| x.1.to_string());
    let r#type = params
        .iter()
        .find(|x| x.0 == "type")
        .map(|x| x.1.to_string());

    unsafe {
        let mut err: DBWError = 0;

        let title: Option<tagbstring> = match title {
            Some(title) => {
                let len = title.len().try_into().unwrap_or(i32::MAX);
                Some(blk2tbstr(
                    CString::new(title).unwrap().into_raw() as *mut u8,
                    len,
                ))
            }
            None => None,
        };
        let tags: Option<tagbstring> = match tags {
            Some(tags) => {
                let len = tags.len().try_into().unwrap_or(i32::MAX);
                Some(blk2tbstr(
                    CString::new(tags).unwrap().into_raw() as *mut u8,
                    len,
                ))
            }
            None => None,
        };
        let r#type: Option<tagbstring> = match r#type {
            Some(r#type) => {
                let len = r#type.len().try_into().unwrap_or(i32::MAX);
                Some(blk2tbstr(
                    CString::new(r#type).unwrap().into_raw() as *mut u8,
                    len,
                ))
            }
            None => None,
        };

        let answer = json_api_find_snippets(
            app.dbh.0,
            match title {
                Some(mut title) => &mut title,
                None => null_mut(),
            },
            match r#type {
                Some(mut r#type) => &mut r#type,
                None => null_mut(),
            },
            match tags {
                Some(mut tags) => &mut tags,
                None => null_mut(),
            },
            &mut err,
        );

        // free allocated CStrings
        let _ = title.map(|x| CString::from_raw(x.data as *mut i8));
        let _ = tags.map(|x| CString::from_raw(x.data as *mut i8));
        let _ = r#type.map(|x| CString::from_raw(x.data as *mut i8));

        *response.body_mut() = Body::from(
            CStr::from_ptr((*answer).data.cast())
                .to_str()
                .unwrap()
                .to_string(),
        );
        *response.status_mut() =
            StatusCode::from_u16(err as u16).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        bdestroy(answer);
    };
    Ok(response)
}

async fn create_snippet_handler(
    req: Request<Body>,
    app: Arc<YNote>,
) -> Result<Response<Body>, hyper::Error> {
    let mut response = Response::new(Body::empty());
    let mut params = url::form_urlencoded::parse(&req.uri().query().unwrap_or_default().as_bytes());
    let edit = match params.find(|x| x.0 == "edit") {
        Some(edit) => edit.1.parse::<bool>().unwrap_or_default(),
        None => false,
    };
    let full_body = hyper::body::to_bytes(req.into_body()).await?;
    let json = unsafe {
        let json = blk2bstr(full_body.as_ptr() as *const c_void, full_body.len() as i32);
        let mut err: DBWError = 0;
        let answer = json_api_create_snippet(app.dbh.0, json, 0, edit.into(), &mut err);
        let ret = CStr::from_ptr((*answer).data.cast())
            .to_str()
            .unwrap()
            .to_string();
        *response.status_mut() =
            StatusCode::from_u16(err as u16).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        bdestroy(json);
        bdestroy(answer);
        ret
    };
    *response.body_mut() = Body::from(json);
    Ok(response)
}

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
                            let snippet = CStr::from_ptr((*snippet).data.cast()).to_str().unwrap().to_string();
                            *response.body_mut() = Body::from(snippet);
                        }
                        DBWError_DBW_ERR_NOT_FOUND => {
                            *response.status_mut() = StatusCode::NOT_FOUND;
                            *response.body_mut() =
                                Body::from(r#"{"status": "error", "msg": "Snippet not found"}"#);
                        }
                        _ => {
                            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                            *response.body_mut() =
                                Body::from(r#"{"status": "error", "msg": "internal error"}"#);
                        }
                    }
                    bdestroy(snippet);
                },
            }
        }
    }
                            Ok(response)
}

async fn handler(req: Request<Body>, app: Arc<YNote>) -> Result<Response<Body>, hyper::Error> {
    let mut response = Response::new(Body::empty());
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => {
            *response.body_mut() = Body::from(r#"{"status": "ook"}"#);
        }
        (&Method::GET, "/api/get_snippet") => {
            return get_snippet_handler(req, app).await;
        }
        (&Method::POST, "/api/create_snippet") => {
            return create_snippet_handler(req, app).await;
        }
        (&Method::GET, "/api/find_snippets") => {
            return find_snippets_handler(req, app).await;
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
            let path = bfromcstr(CStr::from_bytes_with_nul(b"test.db\0").unwrap().as_ptr());
            let h = dbw_connect(
                DBWDBType_DBW_SQLITE3,
                path,
                null_mut(),
            );
            bdestroy(path);
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