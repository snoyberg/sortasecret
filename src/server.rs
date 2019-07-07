extern crate actix_web;
extern crate futures;
extern crate awc;

use super::cli::Server;
use super::keypair::Keypair;
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use std::sync::Arc;
use actix_web::client::{Client, SendRequestError};
use awc::error::JsonPayloadError;
use futures::future::Future;
use std::collections::HashMap;

struct AppState {
    keypair: Arc<Keypair>,
    script: Arc<String>,
    homepage: Arc<String>,
    recaptcha_secret: String,
}

pub fn run(settings: Server) -> Result<(), super::keypair::Error> {
    let script = Arc::new(make_script(&settings));
    let keypair = Arc::new(Keypair::decode_file(&settings.keyfile)?);
    let homepage = Arc::new(make_homepage(&keypair));
    let rs = settings.recaptcha_secret;

    HttpServer::new(move || {
        App::new()
            .data(AppState {
                keypair: keypair.clone(),
                script: script.clone(),
                homepage: homepage.clone(),
                recaptcha_secret: rs.clone(),
            })
            .route("/v1/pubkey", web::get().to(pubkey))
            .route("/v1/encrypt", web::get().to(encrypt))
            .route("/v1/decrypt", web::put().to_async(decrypt))
            .route("/v1/script.js", web::get().to(script_js))
            .route("/v1/show", web::get().to(show_html))
            .route("/", web::get().to(homepage_html))
    })
        .bind(settings.bind)?
        .run()?;

    Ok(())
}

fn pubkey(data: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok().body(&data.keypair.public_hex)
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
struct VerifyRequest {
    secret: String,
    response: String,
}

#[derive(Debug)]
enum VerifyError {
    InvalidJson(JsonPayloadError),
    SendRequest(SendRequestError),
}

impl From<JsonPayloadError> for VerifyError {
    fn from(e: JsonPayloadError) -> VerifyError {
        VerifyError::InvalidJson(e)
    }
}

impl From<SendRequestError> for VerifyError {
    fn from(e: SendRequestError) -> VerifyError {
        VerifyError::SendRequest(e)
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

fn encrypt(encreq: web::Query<EncryptRequest>, data: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok().body(data.keypair.encrypt(&encreq.secret))
}

fn decrypt(decreq: web::Json<DecryptRequest>, data: web::Data<AppState>) -> impl Future<Item=impl Responder, Error=actix_web::Error> {
    let req = VerifyRequest {
        // FIXME simplify the Arc and remove clone usages
        secret: data.recaptcha_secret.clone(),
        response: decreq.token.clone(),
    };
    let keypair = data.keypair.clone();
    let secrets = decreq.secrets.clone();

    Client::default()
        .post("https://www.google.com/recaptcha/api/siteverify")
        .header("User-Agent", "Actix-web")
        .send_form(&req)
        .from_err()
        .and_then(|mut res| res.json().from_err())
        .map(move |res: VerifyResponse| {
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
        })
        // FIXME log the actual error with a UUID for discovery
        .or_else(|err: VerifyError| {
            eprintln!("Error: {:?}", err);
            Ok(HttpResponse::InternalServerError().body("An internal error occurred"))
        })
}

fn script_js(data: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/javascript; charset=utf-8")
        .body(&*data.script)
}

fn homepage_html(data: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(&*data.homepage)
}

fn show_html(encreq: web::Query<EncryptRequest>, data: web::Data<AppState>) -> impl Responder {
    // Check that the secret is actually valid. This also prevents an
    // XSS attack, since only simple hex values will be allowed
    // through.
    match data.keypair.decrypt(&encreq.secret) {
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
      fetch("{}/v1/decrypt", {{
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
        settings.approot,
    )
}
