use bytes::Bytes;
use dbw::{
    bdestroy, bfromcstr, blk2bstr, bstring, dbw_connect, dbw_get_snippet, json_api_create_snippet,
    json_api_find_snippets, json_api_get_snippet, strlen, tagbstring, DBWDBType,
    DBWDBType_DBW_SQLITE3, DBWError, DBWError_DBW_ERR_ALREADY_EXISTS, DBWError_DBW_ERR_NOT_FOUND,
    DBWError_DBW_OK, DBWHandler,
};
use hyper::http::{Request, Response, StatusCode};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Server};
use serde::{Deserialize, Serialize};
use serde_json::{Error, Value};
use std::borrow::{Borrow, Cow};
use std::convert::Infallible;
use std::env::args;
use std::error;
use std::ffi::c_void;
use std::ffi::CStr;
use std::ffi::CString;
use std::fmt;
use std::fs;
use std::mem::ManuallyDrop;
use std::net::SocketAddr;
use std::ops::Deref;
use std::os::raw::{c_char, c_int, c_uchar};
use std::ptr::{null, null_mut};
use std::str;
use std::sync::{Arc, Mutex};
use toml;

use url;

struct YNote {
    dbh: SendPtr<*mut DBWHandler>,
    dbpath: String,
    confpath: String,
    addr: SocketAddr,
}

impl Default for YNote {
    fn default() -> YNote {
        YNote {
            dbh: SendPtr(null_mut()),
            dbpath: "./main.db".to_owned(),
            confpath: "".to_owned(),
            addr: "127.0.0.1:3000".parse().unwrap(),
        }
    }
}

unsafe impl<T> Send for SendPtr<T> {}
unsafe impl<T> Sync for SendPtr<T> {}

enum BstringKind {
    Owned,
    FromCString,
}
struct Bstring {
    k: BstringKind,
    s: bstring,
}
impl Drop for Bstring {
    fn drop(&mut self) {
        println!("bstirng dropped");
        match &self.k {
            BstringKind::Owned => unsafe {
                bdestroy(self.s);
            },
            BstringKind::FromCString => unsafe {
                if !std::ptr::eq(self.s, null()) && !std::ptr::eq((*self.s).data, null()) {
                    let _ = CString::from_raw((*self.s).data.cast());
                    let _ = Box::from_raw(self.s);
                }
            },
        }
    }
}

impl Deref for Bstring {
    type Target = str;

    fn deref<'a>(&'a self) -> &'a str {
        let c_str = unsafe { CStr::from_ptr((*self.s).data.cast()) };
        c_str.to_str().unwrap()
    }
}
impl From<String> for Bstring {
    fn from(item: String) -> Self {
        unsafe {
            let path = CString::from_vec_unchecked(item.into());
            let tb = Box::new(btfromcstr(path.into_raw().cast()));
            assert!(!std::ptr::eq(tb.data, null()));
            Bstring {
                k: BstringKind::FromCString,
                s: Box::into_raw(tb),
            }
        }
    }
}

impl TryInto<Bytes> for Bstring {
    type Error = ();
    fn try_into(self) -> Result<Bytes, Self::Error> {
        if std::ptr::eq(self.s, null()) {
            return Err(());
        }

        unsafe {
            if std::ptr::eq((*self.s).data, null()) {
                return Err(());
            }
            let ret = Ok(Bytes::from(
                CStr::from_ptr((*self.s).data.cast()).to_bytes(),
            ));
            (*self.s).data = null_mut();
            bdestroy(self.s);
            ret
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

fn btfromcstr(s: *mut c_uchar) -> tagbstring {
    tagbstring {
        data: s,
        slen: if std::ptr::eq(s, null()) {
            0
        } else {
            unsafe { strlen(s as *const i8) }
        }
        .try_into()
        .unwrap_or(i32::MAX),
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
                    CString::from_vec_unchecked(title.into_bytes()).into_raw() as *mut u8,
                    len,
                ))
            }
            None => None,
        };
        let tags: Option<tagbstring> = match tags {
            Some(tags) => {
                let len = tags.len().try_into().unwrap_or(i32::MAX);
                Some(blk2tbstr(
                    CString::from_vec_unchecked(tags.into_bytes()).into_raw() as *mut u8,
                    len,
                ))
            }
            None => None,
        };
        let r#type: Option<tagbstring> = match r#type {
            Some(r#type) => {
                let len = r#type.len().try_into().unwrap_or(i32::MAX);
                Some(blk2tbstr(
                    CString::from_vec_unchecked(r#type.into_bytes()).into_raw() as *mut u8,
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
    let mut params: Vec<(Cow<str>, Cow<str>)> =
        url::form_urlencoded::parse(&req.uri().query().unwrap_or_default().as_bytes()).collect();
    //   let params = &req.uri().query();
    // let params = url::Url::parse(&req.uri().to_string()).unwrap().query_pairs();
    let edit = match params.iter().find(|x| x.0 == "tags") {
        Some(edit) => edit.1.parse::<bool>().unwrap_or_default(),
        None => false,
    };
    let id = params.iter().find(|x| x.0 == "id");
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
                    let bsnippet = json_api_get_snippet(app.dbh.0, id, (!edit).into(), &mut err);
                    *response.status_mut() = StatusCode::from_u16(err as u16)
                        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                    if std::ptr::eq(bsnippet, null()) {
                        *response.body_mut() = Body::from("error");
                        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    } else {
                        let snippet = CStr::from_ptr((*bsnippet).data.cast());
                        let snippet: String = snippet.to_str().unwrap().to_owned();
                        *response.body_mut() = Body::from(snippet);
                        bdestroy(bsnippet);
                    }
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

impl YNote {
    fn new() -> YNote {
        YNote {
            ..Default::default()
        }
    }
    fn read_config(self: &mut YNote) {
        if self.confpath == "" {
            return;
        }
        let config = fs::read_to_string(&self.confpath).expect("Couldn't read config");
        let value = config
            .parse::<toml::Value>()
            .expect("Couldn't parse config");
        self.addr = value
            .get("host")
            .map(toml::Value::as_str)
            .unwrap_or(Some("127.0.0.1:3000"))
            .expect("host must be string")
            .parse()
            .expect("Couldn't parse host");

        self.dbpath = value
            .get("db_path")
            .map(toml::Value::as_str)
            .unwrap_or(Some("./test.db"))
            .expect("db_path must be string")
            .to_owned()
    }
    fn parse_cli_options(self: &mut YNote) {
        let mut opts = args();
        while let Some(opt) = opts.next() {
            if opt == "-c" {
                let path = opts.next().expect("-c require argument");
                self.confpath = path;
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut app = YNote::new();
    app.parse_cli_options();
    app.read_config();
    let app = Arc::new(YNote {
        dbh: unsafe {
            let path: Bstring = app.dbpath.to_owned().into();
            let h = dbw_connect(DBWDBType_DBW_SQLITE3, path.s, null_mut());
            assert!(!std::ptr::eq(h, null()));
            SendPtr(h)
        },
        ..Default::default()
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
