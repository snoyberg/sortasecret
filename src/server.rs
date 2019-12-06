extern crate actix_web;
extern crate futures;
extern crate serde_urlencoded;

use super::cli::Server;
use super::keypair::Keypair;
use actix_web::{web, App, HttpResponse, HttpServer, HttpRequest};
use std::sync::Arc;
use std::collections::HashMap;

pub fn run(settings: Server) -> Result<(), super::keypair::Error> {
    let script: Arc<String> = Arc::new(make_script(&settings));
    let keypair = Arc::new(Keypair::decode(&settings.keypair)?);
    let homepage = Arc::new(make_homepage(&keypair));
    let rs = Arc::new(settings.recaptcha_secret);

    HttpServer::new(move || {
        let keypair_pubkey = keypair.clone();
        let keypair_encrypt = keypair.clone();
        let keypair_decrypt = keypair.clone();
        let keypair_show = keypair.clone();
        let script = script.clone();
        let homepage = homepage.clone();
        let rs = rs.clone();

        App::new()
            .route("/v1/pubkey", web::get().to(move || pubkey(keypair_pubkey.clone())))
            .route("/v1/encrypt", web::get().to(move |encreq| encrypt(encreq, keypair_encrypt.clone())))
            .route("/v1/decrypt", web::put().to(move |decreq| decrypt(decreq, keypair_decrypt.clone(), &rs)))
            .route("/v1/script.js", web::get().to(move || script_js(script.clone())))
            .route("/v1/show", web::get().to(move |encreq| show_html(encreq, keypair_show.clone())))
            .route("/", web::get().to(move |_: HttpRequest| homepage_html(homepage.clone())))
    })
        .bind(settings.bind)?
        .run()?;

    Ok(())
}

fn pubkey(keypair: Arc<Keypair>) -> HttpResponse {
    HttpResponse::Ok().body(&keypair.public_hex)
}

#[derive(Deserialize, Debug)]
struct EncryptRequest {
    secret: String,
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

fn encrypt(encreq: web::Query<EncryptRequest>, keypair: Arc<Keypair>) -> HttpResponse {
    HttpResponse::Ok().body(keypair.encrypt(&encreq.secret))
}

async fn site_verify<'a>(body: &VerifyRequest<'a>) -> Result<VerifyResponse, VerifyError> {
    Ok(surf::post("https://www.google.com/recaptcha/api/siteverify")
        .set_header("User-Agent", "surf")
        .body_form(body)?
        .await
        .map_err(|e| VerifyError::Surf(e))?
        .body_json().await?)
}

fn decrypt(decreq: web::Json<DecryptRequest>, keypair: Arc<Keypair>, recaptcha_secret: &str) -> HttpResponse {
    // FIXME evil blocking
    async_std::task::block_on(decrypt_async(decreq, keypair, recaptcha_secret))
}

async fn decrypt_async(decreq: web::Json<DecryptRequest>, keypair: Arc<Keypair>, recaptcha_secret: &str) -> HttpResponse {
    let decreq = decreq.into_inner();
    let req = VerifyRequest {
        // Looks like a copy of this data is necessary, see https://serde.rs/feature-flags.html#-features-rc
        secret: recaptcha_secret,
        response: decreq.token,
    };
    let secrets = decreq.secrets;

    // FIXME Temporary hack: block in here
    let verres = site_verify(&req).await;

    match verres {
        Err(err) => {
            eprintln!("Error: {:?}", err);
            HttpResponse::InternalServerError().body("An internal error occurred")
        }
        Ok(res) => {
            if res.success {
                let decrypted = secrets
                    .into_iter()
                    .map(|secret| {
                        let cleartext = match keypair.decrypt(&secret) {
                            Err(e) => format!("Could not decrypt secret: {:?}", e),
                            Ok(vec) => match String::from_utf8(vec) {
                                Ok(s) => s,
                                Err(e) => format!("Invalid UTF-8 value: {:?}", e),
                            }
                        };
                        (secret, cleartext)
                    })
                .collect();
                HttpResponse::Ok().json(DecryptResponse {decrypted})
            } else {
                HttpResponse::BadRequest().body("Recaptcha fail")
            }
        }
    }
}

fn script_js(body: Arc<String>) -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/javascript; charset=utf-8")
        .body(&*body)
}

fn homepage_html(body: Arc<String>) -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(&*body)
}

fn show_html(encreq: web::Query<EncryptRequest>, keypair: Arc<Keypair>) -> HttpResponse {
    // Check that the secret is actually valid. This also prevents an
    // XSS attack, since only simple hex values will be allowed
    // through.
    match keypair.decrypt(&encreq.secret) {
        Ok(_) => {
            let html = format!(r#"
<!DOCTYPE html>
<html>
  <head>
    <title>Showing you a secret</title>
    <script src="/v1/script.js"></script>
  </head>
  <body>
    <h1>Showing you a secret</h1>
    <button onclick="sortasecret()">Show me the secret</button>
    <b data-sortasecret="{}">Not showing you the secret yet...</b>
  </body>
</html>
"#,
                               encreq.secret);
            HttpResponse::Ok()
                .content_type("text/html; charset=utf-8")
                .body(&html)
        }
        Err(e) => {
            eprintln!("{:?} {}", e, encreq.secret);
            HttpResponse::NotFound().body("Invalid secret")
        }
    }
}

fn make_homepage(keypair: &Keypair) -> String {
    format!(
        r#"
<!DOCTYPE html>
<html>
  <head>
    <title>Sorta Secret</title>
  </head>
  <body>
    <script src="/v1/script.js"></script>
    <h1>Sorta Secret</h1>
    <p><a href="javascript:sortasecret()">Decrypt the secrets below!</a></p>
    <p data-sortasecret="{}"><i>This is a secret</i></p>
  </body>
</html>
"#,
        keypair.encrypt("The secret message has now been decrypted, congratulations!"),
    )
}

fn make_script(settings: &Server) -> String {
    format!(
        r#"
(() => {{
var script = document.createElement("script");
script.setAttribute("src", "https://www.google.com/recaptcha/api.js?render={}");
document.head.appendChild(script);
}})()
function sortasecret() {{
  grecaptcha.ready(() => {{
    grecaptcha.execute("{}", {{action: "homepage"}}).then((token) => {{
      var secrets = [], nodes = document.querySelectorAll("[data-sortasecret]");
      for (var i = 0; i < nodes.length; ++i) {{
        secrets.push(nodes[i].getAttribute("data-sortasecret"));
      }}
      fetch("/v1/decrypt", {{
        method: "PUT",
        body: JSON.stringify({{token: token, secrets: secrets}}),
        headers: {{"content-type": "application/json"}},
      }}).then(res => res.json())
      .then(response => {{
        var nodes = document.querySelectorAll("[data-sortasecret]");
        for (var i = 0; i < nodes.length; ++i) {{
          var node = nodes[i];
          var key = node.getAttribute("data-sortasecret");
          var decrypted = response.decrypted[key];
          node.innerText = decrypted;
        }}
      }})
      .catch(error => console.log("Error: ", JSON.stringify(error)))
    }});
  }});
}}
"#,
        settings.recaptcha_site,
        settings.recaptcha_site,
    )
}
