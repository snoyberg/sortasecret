extern crate cfg_if;
extern crate wasm_bindgen;
#[macro_use]
extern crate serde_derive;

mod cloudflare;
mod secrets;
mod server;
mod utils;

use cfg_if::cfg_if;
use cloudflare::{html, js, static_file};
use rust_embed::RustEmbed;
use snafu::{ResultExt, Snafu};
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
    Askama { source: askama::Error },
    #[snafu(display("Not found: {}", path))]
    NotFound { path: String },
}

impl Error {
    fn into_response(self) -> Result<web_sys::Response> {
        let status = match self {
            Error::NotFound { .. } => 404,
            Error::UrlParse { .. } => 400,
            _ => 500,
        };
        html(
            status,
            format!("<!DOCTYPE html><html><head><title>{error}</title></head><body><h1>Error occurred</h1><pre>{error}</pre></body></html>", error = self),
        )
        .context(Cloudflare)
    }
}

#[wasm_bindgen]
pub async fn respond_wrapper(req: web_sys::Request) -> Result<web_sys::Response, JsValue> {
    respond(req)
        .await
        .map(Ok)
        .unwrap_or_else(Error::into_response)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

fn serve_static(url: &url::Url, name: &str) -> Result<web_sys::Response> {
    let content = Static::get(name).ok_or_else(|| Error::NotFound {
        path: url.path().to_owned(),
    })?;
    static_file(200, name, content.into()).context(Cloudflare)
}

async fn respond(req: web_sys::Request) -> Result<web_sys::Response> {
    let url_string = req.url();
    let url: url::Url = url_string.parse().with_context(|| UrlParse {
        url: url_string.clone(),
    })?;

    Ok(match (req.method() == "GET", url.path()) {
        (true, "/") => html(200, server::homepage_html().context(Server)?).context(Cloudflare)?,
        (true, "/v1/script.js") => {
            js(200, server::script_js().context(Askama)?).context(Cloudflare)?
        }
        (false, "/v1/decrypt") => {
            let text = cloudflare::request_text(&req).await.context(Cloudflare)?;
            let (status, body) = server::decrypt(&text).await;
            html(status, body).context(Cloudflare)?
        }
        (true, "/v1/encrypt") => {
            let (status, body) = server::encrypt(&url).context(Server)?;
            html(status, body).context(Cloudflare)?
        }
        (true, "/v1/show") => {
            let (status, body) = server::show_html(&url).context(Server)?;
            html(status, body).context(Cloudflare)?
        }
        (true, "/favicon.ico") => serve_static(&url, "favicon.ico")?,
        (method, path) => {
            if !method {
                return Err(Error::NotFound {
                    path: url.path().to_owned(),
                });
            }
            if !path.starts_with("/static/") {
                return Err(Error::NotFound {
                    path: url.path().to_owned(),
                });
            }
            serve_static(&url, &path[8..])?
        }
    })
}
