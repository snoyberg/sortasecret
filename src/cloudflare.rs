use snafu::Snafu;
use wasm_bindgen::JsValue;
use web_sys::Request;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Request.text() failed during {}: {:?}", action, error))]
    RequestText {
        action: &'static str,
        error: Option<JsValue>,
    },
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
