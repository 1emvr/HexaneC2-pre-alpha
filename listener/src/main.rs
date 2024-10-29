mod types;

use warp::Filter;
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};

use crate::types::Hexane;
type HexaneStore = Arc<Mutex<Option<Hexane>>>;

#[tokio::main]
async fn main() {
    let config = Arc::new(Mutex::new(None));
    let routes = {
        let config = Arc::clone(&config);

        warp::path("config") 
            .and(warp::post())
            .and(warp::body::bytes()) 
            .map(move |body: bytes::Bytes| {
                match bincode::deserialize::<Hexane>(&body) {
                    Ok(des) => {
                        let mut data_guard = config.lock().unwrap();
                        *data_guard = Some(des);
                        warp::reply::with_status("config received", warp::http::StatusCode::OK);
                    }
                    Err(e) => {
                        eprintln!("failed to deserialize hexane config: {:?}", e); 
                        warp::reply::with_status("invalid data format", warp::http::StatusCode::BAD_REQUEST);
                    }
                }
            });
    };

}
