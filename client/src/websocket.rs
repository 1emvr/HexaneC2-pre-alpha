mod types;
use crate::error::{Result, Error};


//#[derive(serde::Deserialize, serde::Serialize)]
//pub struct RegisterRequest {
//    user_id: usize,
//}

//#[derive(serde::Deserialize, serde::Serialize)]
//pub struct RegisterResponse {
//    url: String,
//}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct Event {
    msg_type: u32,
    user_id:  Option<usize>,
    message:  String,
}

pub struct Client {
    pub user_id: usize,
    pub sender: Option<mpsc::UnboundedSender<Result<Message, warp::Error>>>,
}

