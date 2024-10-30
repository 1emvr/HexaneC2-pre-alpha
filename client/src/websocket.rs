mod error;
mod types;

type Error = crate::error::Error;
type Result<T> = crate::error::Result<T, Rejection>;

use mpsc::UnboundedSender;
use warp::Error as WarpError;
use warp::filters::ws::Message;
use std::{sync, collections};

#[derive(serde::Deserialize, serde::Serialize)]
pub struct Event {
    etype:    u32,
    user_id:  Option<usize>,
    message:  String,
}

pub struct Client {
    pub user_id: usize,
    pub sender:  Option<UnboundedSender<Result<Message, WarpError>>>,
}
type Clients = Arc<Mutex<HashMap<String, Client>>>


#[tokio::main]
async fn main() {
    
}

