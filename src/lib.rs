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
    body: String,
}

#[derive(Deserialize, Debug)]
pub struct Request {
    method: String,
    headers: HashMap<String, String>,
    url: String,
    body: String, // FIXME work with binary data
}

#[wasm_bindgen]
pub async fn respond_wrapper(req: JsValue) -> Result<JsValue, JsValue> {
    let req = req.into_serde().map_err(|e| e.to_string())?;
    let res = respond(req).await.map_err(|e| e.to_string())?;
    let res = JsValue::from_serde(&res).map_err(|e| e.to_string())?;
    Ok(res)
}

fn html(status: u16, body: String) -> Response {
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "text/html; charset=utf-8".to_string());
    Response { status, headers, body }
}

fn js(status: u16, body: String) -> Response {
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "text/javascript; charset=utf-8".to_string());
    Response { status, headers, body }
}

async fn respond(req: Request) -> Result<Response, Box<dyn std::error::Error>> {
    let url: url::Url = req.url.parse()?;
    let res = match (req.method == "GET", url.path()) {
        (true, "/") => html(200, server::homepage_html()?),
        (true, "/v1/script.js") => js(200, server::script_js()?),
        (false, "/v1/decrypt") => {
            let (status, body) = server::decrypt(&req.body).await;
            html(status, body)
        }
        (_method, path) => html(404, format!("Not found: {}", path)),
    };
    Ok(res)
}
