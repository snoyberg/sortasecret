use super::cli::Server;
use keypair::Keypair;
use std::sync::Arc;
use std::collections::HashMap;
use askama::Template;
use hyper::{Request, Body, Response};
use std::convert::Infallible;
use hyper::body::Bytes;

struct MyServer {
    script: Bytes,
    keypair: Keypair,
    homepage: Bytes,
    recaptcha_secret: String,
}

pub async fn run(settings: Server) -> Result<(), Box<dyn std::error::Error>> {
    let script = make_script(&settings).into();
    let keypair = Keypair::decode(&settings.keypair)?;
    let homepage = make_homepage(&keypair).into();
    let my_server = MyServer {
        script,
        keypair,
        homepage,
        recaptcha_secret: settings.recaptcha_secret,
    };

    let my_server = Arc::new(my_server);

    let addr = settings.bind.parse()?;

    let my_service = move |req: Request<Body>| {
        my_server.clone().serve(req)
    };
    let make_my_service = move |_conn: &hyper::server::conn::AddrStream| {
        let my_service = my_service.clone();
        async move {
            Ok::<_, Infallible>(hyper::service::service_fn(my_service))
        }
    };
    hyper::Server::bind(&addr)
        .serve(hyper::service::make_service_fn(make_my_service))
        .await?;

    Ok(())
}

impl MyServer {
    async fn serve(self: Arc<Self>, req: Request<Body>) -> Result<Response<Body>, Infallible> {
        Ok(match (req.method(), req.uri().path()) {
            (&hyper::Method::GET, "/") => {
                self.homepage_html()
            }
            (&hyper::Method::GET, "/v1/script.js") => {
                self.script_js()
            }
            (&hyper::Method::GET, "/v1/show") => {
                match EncryptRequest::from_request(&req) {
                    Some(encreq) => {
                        self.show_html(encreq)
                    }
                    None => {
                        Response::builder()
                            .status(400)
                            .body("Invalid parameters".into())
                            .unwrap()
                    }
                }
            }
            (&hyper::Method::PUT, "/v1/decrypt") => {
                match DecryptRequest::from_request(req).await {
                    Some(decreq) => {
                        decrypt(&self, decreq).await
                    }
                    None => {
                        Response::builder()
                            .status(400)
                            .body("Invalid parameters".into())
                            .unwrap()
                    }
                }
            }
            (&hyper::Method::GET, "/v1/encrypt") => {
                match EncryptRequest::from_request(&req) {
                    Some(encreq) => {
                        self.encrypt(encreq)
                    }
                    None => {
                        Response::builder()
                            .status(400)
                            .body("Invalid parameters".into())
                            .unwrap()
                    }
                }
            }
            _ => {
                Response::builder()
                    .status(404)
                    .body("Not found".into())
                    .unwrap()
            }
        })
    }

    fn encrypt(self: Arc<Self>, encreq: EncryptRequest) -> Response<Body> {
        Response::builder()
            .status(200)
            .body(self.keypair.encrypt(&encreq.secret).into())
            .unwrap()
    }

    fn script_js(self: Arc<Self>) -> Response<Body> {
        Response::builder()
            .status(200)
            .header("Content-Type", "text/javascript; charset=utf-8")
            .body(self.script.clone().into())
            .unwrap()
    }

    fn show_html(self: Arc<Self>, encreq: EncryptRequest) -> Response<Body> {
        // Check that the secret is actually valid. This also prevents an
        // XSS attack, since only simple hex values will be allowed
        // through.
        match self.keypair.decrypt(&encreq.secret) {
            Ok(_) => {
                let html = ShowHtml {
                    secret: &encreq.secret,
                }.render().unwrap();
                Response::builder()
                    .status(200)
                    .header("Content-Type", "text/html; charset=utf-8")
                    .body(html.into())
                    .unwrap()
            }
            Err(e) => {
                eprintln!("{:?} {}", e, encreq.secret);
                Response::builder()
                    .status(400)
                    .body("Invalid secret".into())
                    .unwrap()
            }
        }
    }

    fn homepage_html(self: Arc<Self>) -> Response<Body> {
        Response::builder()
            .status(200)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(self.homepage.clone().into())
            .unwrap()
    }
}

#[derive(Deserialize, Debug)]
struct EncryptRequest {
    secret: String,
}

impl EncryptRequest {
    fn from_request(req: &Request<Body>) -> Option<Self> {
        serde_urlencoded::from_str(req.uri().query()?).ok()
    }
}

#[derive(Deserialize, Debug)]
struct DecryptRequest {
    token: String,
    secrets: Vec<String>,
}

impl DecryptRequest {
    async fn from_request(mut req: Request<Body>) -> Option<Self> {
        use futures_util::stream::StreamExt;

        let mut res: Vec<u8> = Vec::new();
        while let Some(chunk) = req.body_mut().next().await {
            let chunk = chunk.ok()?;
            res.extend(&chunk);
        }
        let decreq = serde_json::from_slice(&res).ok()?;
        Some(decreq)
    }
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

impl From<DecryptResponse> for Body {
    fn from(decres: DecryptResponse) -> Self {
        serde_json::to_vec(&decres).unwrap().into()
    }
}

async fn site_verify<'a>(body: &VerifyRequest<'a>) -> Result<VerifyResponse, VerifyError> {
    Ok(surf::post("https://www.google.com/recaptcha/api/siteverify")
        .set_header("User-Agent", "surf")
        .body_form(body)?
        .await
        .map_err(|e| VerifyError::Surf(e))?
        .body_json().await?)
}

async fn decrypt(my_server: &MyServer, decreq: DecryptRequest) -> Response<Body> {
    let req = VerifyRequest {
        // Looks like a copy of this data is necessary, see https://serde.rs/feature-flags.html#-features-rc
        secret: &my_server.recaptcha_secret,
        response: decreq.token,
    };
    let secrets = decreq.secrets;

    let verres = site_verify(&req).await;

    match verres {
        Err(err) => {
            eprintln!("Error: {:?}", err);
            Response::builder()
                .status(500)
                .body("An internal error occurred".into())
                .unwrap()
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
                Response::builder()
                    .status(200)
                    .header("Content-Type", "application/json")
                    .body(DecryptResponse {decrypted}.into())
                    .unwrap()
            } else {
                Response::builder()
                    .status(400)
                    .body("Recaptcha fail".into())
                    .unwrap()
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
