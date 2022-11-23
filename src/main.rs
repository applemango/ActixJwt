use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use jwt_simple::prelude::*;

#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

#[post("/echo")]
async fn echo(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

async fn manual_hello() -> impl Responder {
    HttpResponse::Ok().body("Hey there!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let token_key = HS256Key::generate();
    let claims = Claims::create(Duration::from_hours(2));

    let token =  match token_key.authenticate(claims) {
        Ok(token) => token,
        Err(_) => return Ok(()),
    };

    let claims = match token_key.verify_token::<NoCustomClaims>(&token, None) {
        Ok(claims) => claims,
        Err(_) => return Ok(()),
    };

    println!("{}", token);
    println!("{:?}", token_key.to_bytes());
    println!("{:?}", claims);

    HttpServer::new(|| {
        App::new()
            .service(hello)
            .service(echo)
            .route("/hey", web::get().to(manual_hello))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}