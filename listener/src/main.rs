mod types;

use warp::Filter;
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};

use crate::types::Hexane;
use crate::types::NetworkOptions

type HexaneStore = Arc<Mutex<Option<Hexane>>>;

#[tokio::main]
async fn main() {
    let config = Arc::new(Mutex::new(None));
    let routes = {
        let config_clone = Arc::clone(&config);

        warp::path("config") 
            .and(warp::post())
            .and(warp::body::bytes()) 
            .map(move |body: bytes::Bytes| {

                match bincode::deserialize::<Hexane>(&body) {
                    Ok(des) => {
                        let mut data_guard = config_clone.lock().unwrap();
                        data_guard.push(des.clone());

                        if let Some(network) = &des.network_cfg {
                            match &network.options {

                                NetworkOptions::Http(http) => {
                                    let endpoints = &http.endpoints;
                                    warp::reply::with_status(format!("http config received: {:?}", endpoints), warp::http::StatusCode::OK);
                                }

                                NetworkOptions::Smb() => {
                                    warp::replay::with_status("smb config received", warp::http::StatusCode::OK);
                                }
                            }
                        }
                        else {
                            eprintln!("error: missing network configuration {:?}", e); 
                            warp::reply::with_status(format!("error: missing network configuration: {:?}", e), warp::http::StatusCode::BAD_REQUEST);
                        }
                    }
                    Err(e) => {
                        eprintln!("failed to deserialize hexane config: {:?}", e); 
                        warp::reply::with_status(format!("failed to deserialize hexane config: {:?}", e), warp::http::StatusCode::BAD_REQUEST);
                    }
                }
            });
    };

}
