use keypair::Keypair;
use askama::Template;
use std::collections::HashMap;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

pub(crate) fn encrypt(url: &url::Url) -> Result<(u16, String), Box<dyn std::error::Error>> {
    match EncryptRequest::from_url(url) {
        Some(encreq) => {
            let keypair = make_keypair()?;
            let encrypted = keypair.encrypt(&encreq.secret)?;
            Ok((200, encrypted))
        }
        None => Ok((400, "Invalid parameters".into())),
    }
}

pub(crate) fn show_html(url: &url::Url) -> Result<(u16, String), Box<dyn std::error::Error>> {
    match EncryptRequest::from_url(url) {
        // Check that the secret is actually valid. This also prevents an
        // XSS attack, since only simple hex values will be allowed
        // through.
        Some(encreq) => match make_keypair()?.decrypt(&encreq.secret) {
            Ok(_) => {
                let html = Homepage {
                    secret: encreq.secret,
                }.render()?;
                Ok((200, html))
            }
            Err(_e) => Ok((400, "Invalid secret".into())),
        }
        None => Ok((400, "Invalid parameters".into())),
    }
}

#[derive(Deserialize, Debug)]
struct EncryptRequest {
    secret: String,
}

impl EncryptRequest {
    fn from_url(url: &url::Url) -> Option<Self> {
        serde_urlencoded::from_str(url.query()?).ok()
    }
}

#[derive(Deserialize, Debug)]
struct DecryptRequest {
    token: String,
    secrets: Vec<String>,
}

struct VerifyRequest<'a> {
    secret: &'a str,
    response: String,
}

#[derive(Debug)]
enum VerifyError {
    IO(std::io::Error),
    SerdeUrl(serde_urlencoded::ser::Error),
    Js(JsValue),
    SerdeJson(serde_json::error::Error),
    NoWindow,
}

impl From<std::io::Error> for VerifyError {
    fn from(e: std::io::Error) -> Self {
        VerifyError::IO(e)
    }
}

impl From<serde_urlencoded::ser::Error> for VerifyError {
    fn from(e: serde_urlencoded::ser::Error) -> Self {
        VerifyError::SerdeUrl(e)
    }
}

impl From<serde_json::error::Error> for VerifyError {
    fn from(e: serde_json::error::Error) -> Self {
        VerifyError::SerdeJson(e)
    }
}

impl From<JsValue> for VerifyError {
    fn from(e: JsValue) -> Self {
        VerifyError::Js(e)
    }
}

#[derive(Deserialize, Debug)]
struct VerifyResponse {
    success: bool,
}

#[derive(Serialize, Debug)]
struct DecryptResponse {
    decrypted: HashMap<String, String>,
}

pub fn worker_global_scope() -> Option<web_sys::ServiceWorkerGlobalScope> {
    js_sys::global().dyn_into::<web_sys::ServiceWorkerGlobalScope>().ok()
}

async fn site_verify<'a>(body: &VerifyRequest<'a>) -> Result<VerifyResponse, VerifyError> {
    use web_sys::{Request, RequestInit, Response};
    let mut opts = RequestInit::new();
    opts.method("POST");
    let form_data = web_sys::FormData::new()?; // web-sys should really require mut here...
    form_data.append_with_str("secret", body.secret)?;
    form_data.append_with_str("response", &body.response)?;
    opts.body(Some(&form_data));
    let request = Request::new_with_str_and_init(
        "https://www.google.com/recaptcha/api/siteverify",
        &opts,
    )?;

    request.headers().set("User-Agent", "surf")?;

    let window = worker_global_scope().ok_or(VerifyError::NoWindow)?;

    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;

    let resp: Response = resp_value.dyn_into()?;

    let json = JsFuture::from(resp.json()?).await?;

    let verres: VerifyResponse = json.into_serde()?;

    Ok(verres)
}

pub(crate) async fn decrypt(body: &str) -> (u16, String) {
    let decreq: DecryptRequest = match serde_json::from_str(body) {
        Ok(x) => x,
        Err(_) => return (400, "Invalid request".to_string()),
    };
    let req = VerifyRequest {
        secret: super::secrets::RECAPTCHA_SECRET,
        response: decreq.token,
    };
    let secrets = decreq.secrets;
    let verres = site_verify(&req).await;

    match verres {
        Err(_err) => (500, "An internal error occurred".into()),
        Ok(res) => {
            if res.success {
                let decrypted = secrets
                    .into_iter()
                    .map(|secret| {
                        let cleartext = match make_keypair().unwrap().decrypt(&secret) {
                            Err(e) => format!("Could not decrypt secret: {:?}", e),
                            Ok(vec) => match String::from_utf8(vec) {
                                Ok(s) => s,
                                Err(e) => format!("Invalid UTF-8 value: {:?}", e),
                            }
                        };
                        (secret, cleartext)
                    })
                    .collect();
                (200, serde_json::to_string(&DecryptResponse {decrypted}).unwrap())
            } else {
                (400, "Recaptcha fail".into())
            }
        }
    }
}

fn make_keypair() -> Result<keypair::Keypair, keypair::Error> {
    keypair::Keypair::decode(super::secrets::KEYPAIR)
}

pub(crate) fn homepage_html() -> Result<String, Box<dyn std::error::Error>> {
    let keypair = make_keypair()?;
    Ok(make_homepage(&keypair)?)
}

#[derive(Template)]
#[template(path = "homepage.html")]
struct Homepage {
    secret: String,
}

fn make_homepage(keypair: &Keypair) -> Result<String, Box<dyn std::error::Error>> {
    Ok(Homepage {
        secret: keypair.encrypt("The secret message has now been decrypted, congratulations!")?,
    }.render()?)
}

#[derive(Template)]
#[template(path = "script.js", escape = "none")]
struct Script<'a> {
    site: &'a str,
}

pub(crate) fn script_js() -> Result<String, askama::Error> {
    Script {
        site: super::secrets::RECAPTCHA_SITE,
    }.render()
}
