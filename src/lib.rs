extern crate cfg_if;
extern crate wasm_bindgen;
#[macro_use]
extern crate serde_derive;

mod utils;
mod secrets;
mod server;

use cfg_if::cfg_if;
use wasm_bindgen::prelude::*;
use std::collections::HashMap;
use rust_embed::RustEmbed;

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

impl Response {
    fn into_web_response(mut self) -> Result<web_sys::Response, JsValue> {
        let mut init = web_sys::ResponseInit::new();

        let headers = wasm_bindgen::JsValue::from_serde(&self.headers).map_err(|e| format!("Could not convert headers: {}", e))?;
        init.status(self.status);
        init.headers(&headers);
        web_sys::Response::new_with_opt_u8_array_and_init(Some(&mut self.body), &init)
    }
}

#[derive(Deserialize, Debug)]
pub struct Request {
    method: String,
    headers: HashMap<String, String>,
    url: String,
    body: String, // FIXME work with binary data
}

#[wasm_bindgen]
pub async fn respond_wrapper(req: JsValue) -> Result<web_sys::Response, JsValue> {
    let req = req.into_serde().map_err(|e| e.to_string())?;
    let res = respond(req).await.map_err(|e| e.to_string())?;
    res.into_web_response()
}

fn html(status: u16, body: String) -> Response {
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "text/html; charset=utf-8".to_string());
    Response { status, headers, body: body.into_bytes() }
}

fn js(status: u16, body: String) -> Response {
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "text/javascript; charset=utf-8".to_string());
    Response { status, headers, body: body.into_bytes() }
}

fn serve_static(name: &str) -> Option<Response> {
    let content = Static::get(name)?;
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), mime_guess::from_path(name).first_or_octet_stream().to_string());
    Some(Response {
        status: 200,
        headers,
        body: content.into(),
    })
}

async fn respond(req: Request) -> Result<Response, Box<dyn std::error::Error>> {
    let url: url::Url = req.url.parse()?;

    Ok(match (req.method == "GET", url.path()) {
        (true, "/") => html(200, server::homepage_html()?),
        (true, "/v1/script.js") => js(200, server::script_js()?),
        (false, "/v1/decrypt") => {
            let (status, body) = server::decrypt(&req.body).await;
            html(status, body)
        }
        (true, "/v1/encrypt") => {
            let (status, body) = server::encrypt(&req.url.parse()?)?;
            html(status, body)
        }
        (true, "/v1/show") => {
            let (status, body) = server::show_html(&req.url.parse()?)?;
            html(status, body)
        }
        (true, "/favicon.ico") => serve_static("favicon.ico").expect("Missing a favicon"),
        (method, path) => {
            let ores = (|| {
                if !method { return None; }
                if !path.starts_with("/static/") { return None; }
                serve_static(&path[8..])
            })();
            ores.unwrap_or_else(|| html(404, format!("Not found: {}", path)))
        }
    })
}
