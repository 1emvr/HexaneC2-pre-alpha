mod types;
mod parser;
mod stream;
mod error;

use crate::error::Result;

use std::sync::mpsc;
use warp::filters::ws::Message;
use warp::Error as WarpError;

pub struct Operator {
    pub user_id: usize,
    pub sender:  Option<UnboundedSender<Result<Message, WarpError>>>
}

pub struct HelloWorld {
    user_id: usize,
}
