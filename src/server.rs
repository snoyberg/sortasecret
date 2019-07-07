extern crate actix_web;

use super::cli::Server;
use super::keypair::Keypair;
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use std::sync::Arc;

struct AppState {
    keypair: Arc<Keypair>,
}

pub fn run(settings: Server) -> Result<(), super::keypair::Error> {
    let keypair = Arc::new(Keypair::decode_file(settings.keyfile)?);

    HttpServer::new(move || {
        App::new()
            .data(AppState {
                keypair: keypair.clone(),
            })
            .route("/v1/pubkey", web::get().to(pubkey))
            .route("/v1/encrypt", web::get().to(encrypt))
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

fn encrypt(encreq: web::Query<EncryptRequest>, data: web::Data<AppState>) -> impl Responder {
    HttpResponse::BadRequest().body(data.keypair.encrypt(&encreq.secret))
}
