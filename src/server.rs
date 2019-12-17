use keypair::Keypair;
use askama::Template;
use std::collections::HashMap;

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
                let html = ShowHtml {
                    secret: &encreq.secret,
                }.render()?;
                Ok((200, html))
            }
            Err(e) => Ok((400, "Invalid secret".into())),
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

#[derive(Serialize, Debug)]
struct VerifyRequest<'a> {
    secret: &'a str,
    response: String,
}

#[derive(Debug)]
enum VerifyError {
    IO(std::io::Error),
    SerdeUrl(serde_urlencoded::ser::Error),
    Surf(surf::Exception),
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

#[derive(Deserialize, Debug)]
struct VerifyResponse {
    success: bool,
}

#[derive(Serialize, Debug)]
struct DecryptResponse {
    decrypted: HashMap<String, String>,
}

async fn site_verify<'a>(body: &VerifyRequest<'a>) -> Result<VerifyResponse, VerifyError> {
    return Ok(VerifyResponse {success:true}); // FIXME remove
    Ok(surf::post("https://www.google.com/recaptcha/api/siteverify")
        .set_header("User-Agent", "surf")
        .body_form(body)?
        .await
        .map_err(|e| VerifyError::Surf(e))?
        .body_json().await?)
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

#[derive(Template)]
#[template(path = "show-html.html")]
struct ShowHtml<'a> {
    secret: &'a str,
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
