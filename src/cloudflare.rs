use std::collections::HashMap;

use snafu::{ResultExt, Snafu};
use wasm_bindgen::JsValue;
use web_sys::{Request, Response};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Request.text() failed during {}: {:?}", action, error))]
    RequestText {
        action: &'static str,
        error: Option<JsValue>,
    },
    #[snafu(display("Could not convert headers: {}", source))]
    CouldNotConvertHeaders { source: serde_json::Error },
    #[snafu(display("Could not create new Response: {:?}", error))]
    CouldNotCreateResponse { error: JsValue },
}

pub async fn request_text(req: &Request) -> Result<String> {
    let text = req.text().map_err(|e| Error::RequestText {
        action: "text() call",
        error: Some(e),
    })?;
    let future = wasm_bindgen_futures::JsFuture::from(text);
    future
        .await
        .map_err(|e| Error::RequestText {
            action: "Promise",
            error: Some(e),
        })?
        .as_string()
        .ok_or(Error::RequestText {
            action: "as_string()",
            error: None,
        })
}

pub fn html(status: u16, body: String) -> Result<Response> {
    let mut body = body.into_bytes();
    response(status, &mut body, "text/html; charset=utf-8")
}

pub fn js(status: u16, body: String) -> Result<Response> {
    let mut body = body.into_bytes();
    response(status, &mut body, "text/javascript; charset=utf-8")
}

pub fn static_file(status: u16, name: &str, mut body: Vec<u8>) -> Result<Response> {
    response(
        status,
        &mut body,
        &mime_guess::from_path(name)
            .first_or_octet_stream()
            .essence_str(),
    )
}

fn response(status: u16, body: &mut [u8], mime: &str) -> Result<Response> {
    let mut init = web_sys::ResponseInit::new();

    let mut headers: HashMap<&str, &str> = HashMap::new();
    headers.insert("Content-Type", mime);
    let headers = wasm_bindgen::JsValue::from_serde(&headers).context(CouldNotConvertHeaders)?;
    init.status(status);
    init.headers(&headers);
    web_sys::Response::new_with_opt_u8_array_and_init(Some(body), &init)
        .map_err(|e| Error::CouldNotCreateResponse { error: e })
}
