use serde::{Serialize,Deserialize};
use actix_web::{web,App,get,HttpServer, dev::ServiceRequest, error::{Error}, HttpMessage};
use std::sync::Mutex;
use actix_web_httpauth::{
    extractors::{AuthenticationError,bearer::{self,BearerAuth}},
    middleware::HttpAuthentication
    
};
use hmac::{Hmac, Mac};
use jwt::VerifyWithKey;
use sha2::Sha256;
use dotenv::dotenv;
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};
mod todolist;
use todolist::service::{self, create_entries,get_entries,update_entry,delete_entry,create_user,basic_auth};

struct AppState {
    todolist_entries : Mutex<Vec<TodolistEntry>>,
    db: Pool<Postgres>,
}

#[derive(Serialize,Deserialize,Clone)]
struct TodolistEntry {
    id: u32,
    date: u64,
    title: String
}

#[derive(Serialize, Deserialize, Clone)]
struct TokenClaims {
    id: i32
}


async fn validator(req: ServiceRequest, credentials: BearerAuth)-> Result<ServiceRequest, (Error, ServiceRequest)> {
    let jwt_secret: String = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let key: Hmac<Sha256> = Hmac::new_from_slice(jwt_secret.as_bytes()).unwrap();
    let token_string = credentials.token();
    let claims: Result<TokenClaims, &str> = token_string.verify_with_key(&key).map_err(|_| "invalid token");

    match claims {
        Ok(value)=>{
            req.extensions_mut().insert(value);
            Ok(req)
        }
        Err(_)=>{
            let config = req.app_data::<bearer::Config>().cloned().unwrap_or_default().scope("");
            Err((AuthenticationError::from(config).into(), req))
        }
    }
}


#[get("/")]
async fn index() -> String{
    "this is a health check route".to_string()
}

#[actix_web::main]
async fn main()-> std::io::Result<()>{
    dotenv().ok();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Error building a connection pool");

    let bearer_middleware = HttpAuthentication::bearer(validator);
    let app_data= web::Data::new(AppState{
        todolist_entries: Mutex::new(vec![]),
        db: pool.clone()
    });

    HttpServer::new(move || {
        App::new().app_data(app_data.clone()).service(index)
        .service(get_entries)
        .service(update_entry)
        .service(delete_entry)
        .service(create_user)
        .service(basic_auth)
        .service(
            web::scope("")
                .wrap(bearer_middleware.clone())
                .service(create_entries),
        )
        // .configure(service::config)
    }).bind(("127.0.0.1",8080))?.run().await
}