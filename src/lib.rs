extern crate cfg_if;
extern crate wasm_bindgen;
#[macro_use]
extern crate serde_derive;

mod cloudflare;
mod secrets;
mod server;
mod utils;

use cfg_if::cfg_if;
use rust_embed::RustEmbed;
use snafu::{ResultExt, Snafu};
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

#[derive(RustEmbed)]
#[folder = "static/"]
struct Static;

cfg_if! {
    // When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
    // allocator.
    if #[cfg(feature = "wee_alloc")] {
        extern crate wee_alloc;
        #[global_allocator]
        static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
    }
}

#[derive(Serialize)]
pub struct Response {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Snafu, Debug)]
enum Error {
    #[snafu(display("Could not parse URL {}: {}", url, source))]
    UrlParse {
        url: String,
        source: url::ParseError,
    },
    #[snafu(display("Error from server code: {}", source))]
    Server { source: Box<dyn std::error::Error> },
    #[snafu(display("{}", source))]
    Cloudflare { source: cloudflare::Error },
    #[snafu(display("Could not convert headers: {}", source))]
    CouldNotConvertHeaders { source: serde_json::Error },
    #[snafu(display("Could not create new Response: {:?}", error))]
    CouldNotCreateResponse { error: JsValue },
    #[snafu(display("Error with askama template: {}", source))]
    Askama {
        source: askama::Error,
    }
}

impl Response {
    fn into_web_response(mut self) -> Result<web_sys::Response> {
        let mut init = web_sys::ResponseInit::new();

        let headers =
            wasm_bindgen::JsValue::from_serde(&self.headers).context(CouldNotConvertHeaders)?;
        init.status(self.status);
        init.headers(&headers);
        web_sys::Response::new_with_opt_u8_array_and_init(Some(&mut self.body), &init)
            .map_err(|e| Error::CouldNotCreateResponse { error: e })
    }
}

#[wasm_bindgen]
pub async fn respond_wrapper(req: web_sys::Request) -> Result<web_sys::Response, JsValue> {
    respond(req).await.and_then(|r| r.into_web_response())
    .map_err(|e| JsValue::from_str(&e.to_string()))
}

fn html(status: u16, body: String) -> Response {
    let mut headers = HashMap::new();
    headers.insert(
        "Content-Type".to_string(),
        "text/html; charset=utf-8".to_string(),
    );
    Response {
        status,
        headers,
        body: body.into_bytes(),
    }
}

fn js(status: u16, body: String) -> Response {
    let mut headers = HashMap::new();
    headers.insert(
        "Content-Type".to_string(),
        "text/javascript; charset=utf-8".to_string(),
    );
    Response {
        status,
        headers,
        body: body.into_bytes(),
    }
}

fn serve_static(name: &str) -> Option<Response> {
    let content = Static::get(name)?;
    let mut headers = HashMap::new();
    headers.insert(
        "Content-Type".to_string(),
        mime_guess::from_path(name)
            .first_or_octet_stream()
            .to_string(),
    );
    Some(Response {
        status: 200,
        headers,
        body: content.into(),
    })
}

async fn respond(req: web_sys::Request) -> Result<Response> {
    let url_string = req.url();
    let url: url::Url = url_string.parse().with_context(|| UrlParse {
        url: url_string.clone(),
    })?;

    Ok(match (req.method() == "GET", url.path()) {
        (true, "/") => html(200, server::homepage_html().context(Server)?),
        (true, "/v1/script.js") => js(200, server::script_js().context(Askama)?),
        (false, "/v1/decrypt") => {
            let text = cloudflare::request_text(&req).await.context(Cloudflare)?;
            let (status, body) = server::decrypt(&text).await;
            html(status, body)
        }
        (true, "/v1/encrypt") => {
            let (status, body) = server::encrypt(&url).context(Server)?;
            html(status, body)
        }
        (true, "/v1/show") => {
            let (status, body) = server::show_html(&url).context(Server)?;
            html(status, body)
        }
        (true, "/favicon.ico") => serve_static("favicon.ico").expect("Missing a favicon"),
        (method, path) => {
            let ores = (|| {
                if !method {
                    return None;
                }
                if !path.starts_with("/static/") {
                    return None;
                }
                serve_static(&path[8..])
            })();
            ores.unwrap_or_else(|| html(404, format!("Not found: {}", path)))
        }
    })
}
