mod types;
mod parser;
mod stream;
mod error;

use std::env;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use log::{info, error};

use serde_json::from_slice;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{accept_async, tungstenite::protocol::Message};
use futures::{StreamExt, SinkExt};

use crate::parser::{Parser, create_parser};
use crate::types::{Hexane, MessageType};

type ConfigStore = Arc<Mutex<Vec<Hexane>>>;
static CONFIGS: ConfigStore = Arc::new(Mutex::new(Vec::new()));

// NOTE: client/server messaging
// TODO: http_server/implant messaging

async fn parse_config(buffer: Vec<u8>) -> String {
    match from_slice::<Hexane>(&buffer) {

        Ok(hexane) => {
            if let Ok(mut configs) = CONFIGS.lock() {
                configs.push(hexane);

                info!("parse_config: hexane push success");
                return "200 OK".to_string();
            }
            else {
                error!("parse_config: error on config lock");
                return "200 OK".to_string(); // always return "200 OK" in case of response enumeration 
            }
        }
        Err(e)=> {
            error!("parse_config: parser error");
            return "200 OK".to_string();
        }
    }
}

async fn process_message(text: String) -> String {
    let parser = create_parser(text.into_bytes());

    match parser.msg_type {
        TypeConfig => {
            let rsp = parse_config(parser.buffer).await;
            return rsp;
        }
        _ => {
            error!("process_message: unknown message type");
            return "200 OK".to_string();
        }
    }
}

async fn handle_connection(stream: TcpStream) {
    let ws_stream = match accept_async(stream).await {
        Ok(ws) => ws,
        Err(e) => {
            error!("handle_connection: error during websocket handshake: {}", e);
            return
        }
    };

    let (mut sender, mut receiver) = ws_stream.split();
    while let Some(msg) = receiver.next().await {
        match msg {

            Ok(_) => (),
            Ok(Message::Text(text)) => { // String
                let rsp = process_message(text).await;
                if let Err(e) = sender.send(Message::Text(rsp)).await {
                    error!("handle_connection: error sending message: {}", e);
                }
            }
            Ok(Message::Close(_)) => {
                info!("handle_connection: client closing connection");
                break;
            }
            Err(e)=> {
                error!("handle_connection: error processing message: {}", e);
                break;
            }
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let addr = env::args().nth(1).unwrap_or_else(|| "127.0.0.1:3000".to_string());
    let addr: SocketAddr = addr.parse().expect("tokio::main: invalid address");

    let listener = TcpListener::bind(&addr).await.expect("tokio::main: could not bind");
    info!("listening on: {}", addr);

    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(handle_connection(stream));
    }
}
