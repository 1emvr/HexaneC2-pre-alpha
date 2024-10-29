mod types;

use warp::Filter;
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};

use crate::types::Hexane;

#[tokio::main]
async fn main() {
    let config = Arc::new(Mutex::new(Hexane));

    // TODO: might just pass the entire Hexane struct from the client 

    let routes = {
        let config = Arc::clone(&config);

        warp::path("config") 
            .and(warp::post())
            .and(warp::body::json()) // TODO: send the SerdeJson config from client to http://ip/config during build time
            .map(move |new_config: Config| {
                let mut config_guard = config.lock().unwrap();     

                *config_guard = new_config;
                warp::reply::with_status("config updated", warp::http::StatusCode::OK)
            });
    };

    let routes = warp::any()
        .and(warp::path::tail())
        .and(warp::method())
        .and(warp::body::bytes())
        .and(with_config(config.clone()))
        .map(
            | tail: warp::filters::path::Tail, method: warp::http::Method, body: bytes::Bytes, config: Arc<Mutex<Hexane>> | {

            }
        );
}
