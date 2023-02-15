use std::hash::Hash;

use actix_web::{get,post,put,delete,HttpResponse, Responder, web::{Data,Json,ReqData},web, error::HttpError};
use crate::{AppState, TodolistEntry, TokenClaims};
use super::models::{CreateEntryData,UpdateEntryData};
use jwt::{SignWithKey, token::verified};
use serde::{Deserialize,Serialize};
use sha2::Sha256;
use hmac::{Hmac,Mac};
use actix_web_httpauth::extractors::basic::BasicAuth;
use argonautica::{Hasher, Verifier};
use sqlx::{self, FromRow};


#[derive(Serialize,Deserialize)]
struct CreateUserBody{
    username: String,
    password: String
}

#[derive(Serialize,FromRow)]
struct UserNoPassword{
    id: i32,
    username: String,
}

#[derive(Serialize,FromRow)]
struct AuthUser{
    id: i32,
    username: String,
    password: String
}

#[post("/user")]
async fn create_user(state : Data<AppState>, body : Json<CreateUserBody>)-> impl Responder{
    let user: CreateUserBody = body.into_inner();
    let hash_secret: String = std::env::var("HASH_SECRET").expect("HASH_SECRET must be set");
    let mut hasher= Hasher::default();
    let hash = hasher.with_password(user.password).with_secret_key(hash_secret).hash().unwrap();
    println!("kk");
    match sqlx::query_as::<_,UserNoPassword>(
        "INSERT INTO users (username, password)
        VALUES ($1, $2)
        RETURNING id, username"
    ).bind(user.username).bind(hash).fetch_one(&state.db).await{
        Ok(user)=> HttpResponse::Ok().json(user),
        Err(error)=> HttpResponse::InternalServerError().json(format!("{:?} error from db",error))
    }
}

#[post("/auth")]
async fn basic_auth(state : Data<AppState>, creddentials: BasicAuth)-> impl Responder{
    let jwt_secret : Hmac<Sha256>= Hmac::new_from_slice(
        std::env::var("JWT_SECRET").expect("JWT_SECRET must be set!").as_bytes()
    ).unwrap();
    let username = creddentials.user_id();
    let password = creddentials.password();

    match password {
        None => HttpResponse::Unauthorized().json("Must Provide username and password"),
        Some(pass)=> {
            match sqlx::query_as::<_,AuthUser>(
                "SELECT id, username, password FROM users WHERE username =$1"
            ).bind(username.to_string())
            .fetch_one(&state.db)
            .await
            {
                Ok(user)=> {
                    let hash_secret= std::env::var("HASH_SECRET").expect("HASH_SECRET must be set!");
                    let mut verifier = Verifier::default();
                    let is_valid = verifier.with_hash(user.password).with_password(pass).with_secret_key(hash_secret).verify().unwrap();

                    if is_valid {
                        let claims = TokenClaims {
                            id: user.id
                        };
                        let token_str = claims.sign_with_key(&jwt_secret).unwrap();
                        HttpResponse::Ok().json(token_str)
                    }
                    else{
                        HttpResponse::Unauthorized().json("Incorrect username")
                    }
                },
                Err(error)=> HttpResponse::InternalServerError().json(format!("{:?}",error)),
            }
        }
    }
}


#[get("/todolist/entries")]
async fn get_entries(data: web::Data<AppState>)-> impl Responder{
    HttpResponse::Ok().json(data.todolist_entries.lock().unwrap().to_vec())
}

#[post("/todolist/entries")]
async fn create_entries(data: web::Data<AppState>, param_obj: web::Json<CreateEntryData>)-> impl Responder{
    // match req_user {
    //     Some(user)=> {
    //         let mut Todo_list_entries = data.todolist_entries.lock().unwrap();
    //         let mut max_id : u32= 0;
    //         for i in 0..Todo_list_entries.len(){
    //             if Todo_list_entries[i].id > max_id {
    //                 max_id = Todo_list_entries[i].id;
    //             }
    //         }
    //         Todo_list_entries.push(TodolistEntry { 
    //             id: max_id+1,
    //             date: param_obj.date,
    //             title: param_obj.title.clone() 
    //         });
    //         HttpResponse::Ok().json(Todo_list_entries.to_vec())
    //     },
    //     _=> HttpResponse::Unauthorized().json("unable to verify identity"),
    // }
    let mut Todo_list_entries = data.todolist_entries.lock().unwrap();
    let mut max_id : u32= 0;
    for i in 0..Todo_list_entries.len(){
        if Todo_list_entries[i].id > max_id {
            max_id = Todo_list_entries[i].id;
        }
    }
    Todo_list_entries.push(TodolistEntry { 
        id: max_id+1,
        date: param_obj.date,
        title: param_obj.title.clone() 
    });
    HttpResponse::Ok().json(Todo_list_entries.to_vec())
}


#[put("/todolist/entries/{id}")]
async fn update_entry(data: web::Data<AppState>, path : web::Path<u32>, param_obj: web::Json<UpdateEntryData>)-> impl Responder{
    let id = path.into_inner();
    let mut todo_list_entries = data.todolist_entries.lock().unwrap();
    for i in 0..todo_list_entries.len(){
        if todo_list_entries[i].id == id {
            todo_list_entries[i].title = param_obj.title.clone();
            break;
        }
    }
    HttpResponse::Ok().json(todo_list_entries.to_vec())
}

#[delete("/todolist/entries/{id}")]
async fn delete_entry(data: web::Data<AppState>, path : web::Path<u32>) -> impl Responder{
    let mut todo_list_entries = data.todolist_entries.lock().unwrap();
    let id = path.into_inner();
    *todo_list_entries = todo_list_entries.to_vec().into_iter().filter(|x| x.id != id).collect();
    HttpResponse::Ok().json(todo_list_entries.to_vec())
}


// pub fn config(cfg: &mut web::ServiceConfig){
//     cfg.service(get_entries).service(update_entry).service(delete_entry).service(create_user).service(basic_auth);  
// }