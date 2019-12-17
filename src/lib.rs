extern crate cfg_if;
extern crate wasm_bindgen;
#[macro_use]
extern crate serde_derive;

mod utils;

use cfg_if::cfg_if;
use wasm_bindgen::prelude::*;
use std::collections::HashMap;
use askama::Template;

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

#[derive(Template)]
#[template(path = "homepage.html")]
struct Homepage<'a> {
    headers: &'a HashMap<String, String>
}

#[derive(Template)]
#[template(path = "submit.html")]
struct Submit<'a> {
    body: &'a str,
}

async fn respond(req: Request) -> Result<Response, Box<dyn std::error::Error>> {
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "text/html; charset=utf-8".to_string());
    let url: url::Url = req.url.parse()?;
    let res = match url.path() {
        "/" => Response {
            status: 200,
            headers,
            body: Homepage { headers: &req.headers }.render()?  },
        "/submit" => Response {
            status: 200,
            headers,
            body: Submit { body: &req.body }.render()?
        },
        path => Response {
            status: 404,
            headers,
            body: format!("Not found: {}", path),
        },
    };
    Ok(res)
}
