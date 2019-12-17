use keypair::Keypair;
use askama::Template;
use std::collections::HashMap;

/*
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
*/

/*
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
*/

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
    return Ok(VerifyResponse { success: true }); // FIXME!
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

/*
#[derive(Template)]
#[template(path = "show-html.html")]
struct ShowHtml<'a> {
    secret: &'a str,
}
*/

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

fn make_homepage(keypair: &Keypair) -> Result<String, askama::Error> {
    Homepage {
        secret: keypair.encrypt("The secret message has now been decrypted, congratulations!"),
    }.render()
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
