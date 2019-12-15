extern crate actix_web;
extern crate futures;
extern crate serde_urlencoded;

use super::cli::Server;
use super::keypair::Keypair;
use actix_web::{web, App, HttpResponse, HttpServer, HttpRequest};
use std::sync::Arc;
use std::collections::HashMap;
use askama::Template;

struct MyServer {
    script: String,
    keypair: Keypair,
    homepage: String,
    recaptcha_secret: String,
}

pub fn run(settings: Server) -> Result<(), super::keypair::Error> {
    let keypair = Keypair::decode(&settings.keypair)?;
    let homepage = make_homepage(&keypair);
    let my_server = MyServer {
        script: make_script(&settings),
        keypair,
        homepage,
        recaptcha_secret: settings.recaptcha_secret,
    };

    let my_server = Arc::new(my_server);

    HttpServer::new(move || {
        let my_server1 = my_server.clone();
        let my_server2 = my_server.clone();
        let my_server3 = my_server.clone();
        let my_server4 = my_server.clone();
        let my_server5 = my_server.clone();
        let my_server6 = my_server.clone();

        App::new()
            .route("/v1/pubkey", web::get().to(move || my_server1.pubkey()))
            .route("/v1/encrypt", web::get().to(move |encreq| my_server2.encrypt(encreq)))
            .route("/v1/decrypt", web::put().to(move |decreq| my_server3.decrypt(decreq)))
            .route("/v1/script.js", web::get().to(move || my_server4.script_js()))
            .route("/v1/show", web::get().to(move |encreq| my_server5.show_html(encreq)))
            .route("/", web::get().to(move |_: HttpRequest| my_server6.homepage_html()))
    })
        .bind(settings.bind)?
        .run()?;

    Ok(())
}

impl MyServer {
    fn pubkey(&self) -> HttpResponse {
        HttpResponse::Ok().body(&self.keypair.public_hex)
    }

    fn encrypt(&self, encreq: web::Query<EncryptRequest>) -> HttpResponse {
        HttpResponse::Ok().body(self.keypair.encrypt(&encreq.secret))
    }

    fn decrypt(&self, decreq: web::Json<DecryptRequest>) -> HttpResponse {
        // FIXME evil blocking
        async_std::task::block_on(decrypt_async(self, decreq))
    }

    fn script_js(&self) -> HttpResponse {
        HttpResponse::Ok()
            .content_type("text/javascript; charset=utf-8")
            .body(&self.script)
    }

    fn show_html(&self, encreq: web::Query<EncryptRequest>) -> HttpResponse {
        // Check that the secret is actually valid. This also prevents an
        // XSS attack, since only simple hex values will be allowed
        // through.
        match self.keypair.decrypt(&encreq.secret) {
            Ok(_) => {
                let html = ShowHtml {
                    secret: &encreq.secret,
                }.render().unwrap();
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

    fn homepage_html(&self) -> HttpResponse {
        HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(&self.homepage)
    }
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

async fn site_verify<'a>(body: &VerifyRequest<'a>) -> Result<VerifyResponse, VerifyError> {
    Ok(surf::post("https://www.google.com/recaptcha/api/siteverify")
        .set_header("User-Agent", "surf")
        .body_form(body)?
        .await
        .map_err(|e| VerifyError::Surf(e))?
        .body_json().await?)
}

async fn decrypt_async(my_server: &MyServer, decreq: web::Json<DecryptRequest>) -> HttpResponse {
    let decreq = decreq.into_inner();
    let req = VerifyRequest {
        // Looks like a copy of this data is necessary, see https://serde.rs/feature-flags.html#-features-rc
        secret: &my_server.recaptcha_secret,
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
                        let cleartext = match my_server.keypair.decrypt(&secret) {
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

#[derive(Template)]
#[template(path = "show-html.html")]
struct ShowHtml<'a> {
    secret: &'a str,
}

#[derive(Template)]
#[template(path = "homepage.html")]
struct Homepage {
    secret: String,
}

fn make_homepage(keypair: &Keypair) -> String {
    Homepage {
        secret: keypair.encrypt("The secret message has now been decrypted, congratulations!"),
    }.render().unwrap()
}

#[derive(Template)]
#[template(path = "script.js", escape = "none")]
struct Script<'a> {
    site: &'a str,
}

fn make_script(settings: &Server) -> String {
    Script {
        site: &settings.recaptcha_site,
    }.render().unwrap()
}
