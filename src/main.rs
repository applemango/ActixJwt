use actix_web::{get, post, web, App, HttpServer, Responder, Result, error, HttpResponse, HttpRequest};
use jwt_simple::prelude::*;
use derive_more::{Display, Error};
use serde::{Serialize, Deserialize};
use rusqlite::Connection;
use uuid::{uuid, Uuid};

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

#[derive(Serialize, Deserialize)]
struct TokenClaims {
    refresh: bool,
}

#[derive(Serialize)]
struct User {
    id: i32,
    username: String,
    password: String,
}


#[post("/register")]
async fn create_user(data: web::Json<CreateTokenRequest>) -> Result<impl Responder, MyError> {
    let db_con = match Connection::open("app.db") {
        Ok(connection) => connection,
        Err(_) => {
            return Err(MyError {name: "db connection error"})
        }
    };

    let mut statement = match db_con.prepare("INSERT INTO user ( username, password ) values ( ?1, ?2 )") {
        Ok(statement) => statement,
        Err(_) => return Err(MyError {name: "Failed to prepare query".into()}),
    };

    let mut _r = match statement.execute(&[&data.username, &data.password]) {
        Ok(r) => r,
        Err(_) => return Err(MyError {name: "Failed"})
    };

    Ok(HttpResponse::Ok().body("Created"))
}


#[post("/token")]
async fn create_token(data: web::Json<CreateTokenRequest>) -> Result<impl Responder, MyError> {
    /*if !(data.username == "apple" && data.password == "mango") {
        return Err(MyError {name: "Invalid username or password"})
    }*/

    let db_con = match Connection::open("app.db") {
        Ok(connection) => connection,
        Err(_) => {
            return Err(MyError {name: "db connection error"})
        }
    };

    let u = match db_con.query_row("SELECT id, username, password FROM user WHERE username = ( ?1 )", [&data.username], |row| {
        Ok(User {
            id: row.get(0)?,
            username: row.get(1)?,
            password: row.get(2)?
        })
    }) {
        Ok(u) => u,
        Err(_) => {
            return Err(MyError {name: "not found"})
        }
    };

    if !(data.username == u.username && data.password == u.password) {
        return Err(MyError {name: "Invalid username or password"})
    }
    
    let token_key = HS256Key::from_bytes(b"secret");

    let token_claims = TokenClaims {
        refresh: false,
    };
    let claims = Claims::with_custom_claims(token_claims, Duration::from_mins(15)).with_subject(u.id).with_jwt_id(Uuid::new_v4().to_string());
    let token =  match token_key.authenticate(claims) {
        Ok(token) => token,
        Err(_) => return Err(MyError {name : "Invalid token"}),
    };

    let token_claims = TokenClaims {
        refresh: true,
    };
    let claims_ = Claims::with_custom_claims(token_claims, Duration::from_hours(24)).with_subject(u.id).with_jwt_id(Uuid::new_v4().to_string());
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
    let claims = Claims::with_custom_claims(token_claims, Duration::from_mins(15)).with_subject(1).with_jwt_id(Uuid::new_v4().to_string());
    let token =  match token_key.authenticate(claims) {
        Ok(token) => token,
        Err(_) => return Err(MyError {name : "Invalid token"}),
    };

    Ok(web::Json(CreateRefreshTokenResponse {
        token: token
    }))
}


#[post("/logout")]
async fn logout_user(req: HttpRequest) -> Result<impl Responder, MyError> {
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

    let sub;
    let uuid;
    let exp;
    match claims.subject {
        Some(d) => sub = d,
        None => return Err(MyError {name : "Invalid token"})
    }
    match claims.jwt_id {
        Some(d) => uuid = d,
        None => return Err(MyError {name : "Invalid token"})
    }
    match claims.expires_at {
        Some(d) => exp = d.as_millis(),
        None => return Err(MyError {name : "Invalid token"})
    }

    let db_con = match Connection::open("app.db") {
        Ok(connection) => connection,
        Err(_) => {
            return Err(MyError {name: "db connection error"})
        }
    };
    let mut statement = match db_con.prepare("INSERT INTO tokenblocklist ( user, token, uuid, exp ) values ( ?1, ?2, ?3, ?4 )") {
        Ok(statement) => statement,
        Err(_) => return Err(MyError {name: "Failed to prepare query".into()}),
    };

    let mut _r = match statement.execute((&sub, token, &uuid, &exp)) {
        Ok(r) => r,
        Err(_) => return Err(MyError {name: "Failed"})
    };

    Ok(HttpResponse::Ok().body("Deleted"))
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

    let db_con = match Connection::open("app.db") {
        Ok(connection) => connection,
        Err(_) => {
            return Err(MyError {name: "db connection error"})
        }
    };

    let uuid;
    match claims.jwt_id {
        Some(d) => uuid = d,
        None => return Err(MyError {name : "Invalid token"})
    }

    let u = match db_con.query_row("SELECT uuid FROM tokenblocklist WHERE uuid = ( ?1 )", [&uuid], |_| {
        Ok(true)
    }) {
        Ok(_) => {
            return Err(MyError {name : "Invalid token"})
        },
        Err(_) => true
    };

    if !u {
        return Err(MyError {name : "Invalid token"})
    }

    if claims.custom.refresh {
        return Err(MyError {name : "Invalid token"})
    }
    
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
    {
        let conn = Connection::open("app.db").unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username STRING UNIQUE NOT NULL,
                password STRING NOT NULL
            )",
            ()
        ).unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS tokenblocklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user INTEGER,
                token STRING,
                uuid STRING,
                exp INTEGER
            )",
            ()
        ).unwrap();
    }
    HttpServer::new(|| {
        App::new()
            .service(create_token)
            .service(refresh_token)
            .service(create_user)
            .service(logout_user)
            .service(hello)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}