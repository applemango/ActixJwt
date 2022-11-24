use actix_web::{get, post, web, App, HttpServer, Responder, Result, error, HttpResponse, HttpRequest};
use jwt_simple::prelude::*;
use derive_more::{Display, Error};
use serde::{Serialize, Deserialize};

use actix_web::http::header::Header;
use actix_web_httpauth::headers::authorization::{Authorization, Basic};

#[display(fmt = "my error: {}", name)]
#[derive(Debug, Display, Error)]
struct MyError {
    name: &'static str,
}
impl error::ResponseError for MyError {}

#[derive(Deserialize)]
struct CreateTokenRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct CreateTokenResponse {
    token: String,
    refresh_token: String,
}

#[derive(Serialize)]
struct CreateRefreshTokenResponse {
    token: String,
}

//#[derive(Debug)]
#[derive(Serialize, Deserialize)]
struct TokenClaims {
    refresh: bool,
}

#[post("/token")]
async fn create_token(data: web::Json<CreateTokenRequest>) -> Result<impl Responder, MyError> {
    if !(data.username == "apple" && data.password == "mango") {
        return Err(MyError {name: "Invalid username or password"})
    }
    
    let token_key = HS256Key::from_bytes(b"secret");
    println!("{:?}", token_key.to_bytes());

    let token_claims = TokenClaims {
        refresh: false,
    };
    let claims = Claims::with_custom_claims(token_claims, Duration::from_mins(15)).with_subject(1);
    let token =  match token_key.authenticate(claims) {
        Ok(token) => token,
        Err(_) => return Err(MyError {name : "Invalid token"}),
    };

    let token_claims = TokenClaims {
        refresh: true,
    };
    let claims_ = Claims::with_custom_claims(token_claims, Duration::from_hours(24)).with_subject(1);
    let refresh_token_ =  match token_key.authenticate(claims_) {
        Ok(token) => token,
        Err(_) => return Err(MyError {name : "Invalid token"}),
    };
    
    Ok(web::Json(CreateTokenResponse {
        token: token,
        refresh_token: refresh_token_,
    }))
}

#[post("/refresh")]
async fn refresh_token(req: HttpRequest) -> Result<impl Responder, MyError> {
    fn get_content_type<'a>(req: &'a HttpRequest) -> Option<&'a str> {
        req.headers().get("Authorization")?.to_str().ok()
    }
    let token;
    if let Some(t) = get_content_type(&req) {
        token = &t[7..];
    } else {
        return Err(MyError {name : "Invalid token"})
    }

    let token_key = HS256Key::from_bytes(b"secret");
    let claims = match token_key.verify_token::<TokenClaims>(&token, None) {
        Ok(claims) => claims,
        Err(_) => return Err(MyError {name : "Invalid token"}),
    };

    if ! claims.custom.refresh {
        return Err(MyError {name : "Invalid token"})
    }

    let token_claims = TokenClaims {
        refresh: false,
    };
    let claims = Claims::with_custom_claims(token_claims, Duration::from_mins(15)).with_subject(1);
    let token =  match token_key.authenticate(claims) {
        Ok(token) => token,
        Err(_) => return Err(MyError {name : "Invalid token"}),
    };

    Ok(web::Json(CreateRefreshTokenResponse {
        token: token
    }))
}

#[get("/hello")]
async fn hello(req: HttpRequest) -> Result<impl Responder, MyError> {
    fn get_content_type<'a>(req: &'a HttpRequest) -> Option<&'a str> {
        req.headers().get("Authorization")?.to_str().ok()
    }
    let token;
    if let Some(t) = get_content_type(&req) {
        token = &t[7..];
    } else {
        return Err(MyError {name : "Invalid token"})
    }

    let token_key = HS256Key::from_bytes(b"secret");

    let claims = match token_key.verify_token::<TokenClaims>(&token, None) {
        Ok(claims) => claims,
        Err(_) => return Err(MyError {name : "Invalid token"}),
    };

    if claims.custom.refresh {
        return Err(MyError {name : "Invalid token"})
    }
    //println!("{:#?}", claims);
    Ok(HttpResponse::Ok().body("Hello world!"))
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    /*
    let token_key = HS256Key::generate();
    let claims = Claims::create(Duration::from_hours(2));

    let token =  match token_key.authenticate(claims) {
        Ok(token) => token,
        Err(_) => return Ok(()),
    };

    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NjkxNzc3MDMsImV4cCI6MTY2OTE4NDkwMywibmJmIjoxNjY5MTc3NzAzfQ.ORnRQsTbvr_j2ARf2WdmUO2wD8JDOrGr36cjOZMRTKE";

    let claims = match token_key.verify_token::<NoCustomClaims>(&token, None) {
        Ok(claims) => claims,
        Err(_) => {
            println!("invalid token");
            return Ok(())
        },
    };

    println!("{}", token);
    println!("{:?}", token_key.to_bytes());
    println!("{:?}", claims);
    */

    HttpServer::new(|| {
        App::new()
            .service(create_token)
            .service(refresh_token)
            .service(hello)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}