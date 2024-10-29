mod types;

use warp::Filter;
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::types::Hexane;
use crate::types::NetworkOptions

type HexaneStore = Arc<Mutex<Vec<Hexane>>>;
type EndpointStore = Ac<Mutext<HashSet<String>>>;

#[tokio::main]
async fn main() {
    let instances: HexaneStore = Arc::new(Mutex::new(None));
    let endpoints: EndpointStore = Arc::new(Mutex::new(HashSet::new())); 

    let base_route = warp::path::end()
        .map(|| "hexane listener is running");

    // NOTE: dynamic router
    let dynamic_routes = {
        let endpoints = Arc::clone(&endpoints);

        warp::path::param::<String>()
            .and_then(move |endpoint: String| {
                let endpoints = endpoints.lock().unwrap();
                if endpoints.contains(&endpoint) {
                    async move {
                        Ok::<_, warp::Rejection>(format!("handling request for: {}", endpoint))
                    }
                }
                else {
                    async move {
                        Err(warp::reject::not_found())
                    }
                }
            })
    }

    let config_route = {
        let instances_clone = Arc::clone(&instances);
        let endpoints_clone = Arc::clone(&endpoints);

        warp::path("instances") 
            .and(warp::post())
            .and(warp::body::bytes()) 
            .map(move |body: bytes::Bytes| {

                // NOTE: deserialize
                match bincode::deserialize::<Hexane>(&body) {

                    Ok(des) => {
                        let mut data_guard = instances_clone.lock().unwrap();
                        data_guard.push(des.clone());

                        if let Some(network) = &des.network_cfg {
                            match &network.options {

                                NetworkOptions::Http(http) => {
                                    let mut endpoint_guard = endpoints.lock().unwrap();
                                    for endpoint in &http.endpoints {
                                        endpoint_guard.insert(endpoint.clone());
                                    }

                                    println!("http config recieved");
                                    warp::reply::with_status("http config received", warp::http::StatusCode::OK);
                                }

                                NetworkOptions::Smb() => {
                                    println!("smb config recieved");
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

    let routes = base_route
        .or(dynamic_routes)
        .or(config_route);

    warp::serve(routines).run(([127, 0, 0, 1], 3000)).await;

}
