mod types;
mod parser;
mod stream;
mod error;

use crate::error::{Error, Result};

use std::env;
use std::net::SocketAddr;

use futures::{StreamExt, SinkExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{
    accept_async,
    tungstenite::protocol::Message
};


// NOTE: client-side connection handler for operators

async fn handle_connection(stream: TcpStream) {
    let ws = match accept_async(stream).await {
        Ok(ws) => ws,
        Err(e) => {
            eprintln!("error during websocket handshake: {}", e);
            return
        }
    };

    let (mut sender, mut receiver) = ws.split();
    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                let body = text.chars().collect();

                // TODO: message processing
                let fake_resp = "ayooooooo".to_string();
                if let Err(e) = sender.send(Message::Text(fake_resp)).await {
                    eprintln!("error sending message: {}", e);
                }
            },
            Ok(Message::Close(_)) => {

            },
            Ok(_) => (),
            Err(e) => {
                eprintln!("error processing message: {}", e);
                break;
            }
        }
    }
}


#[tokio::main]
async fn main() {
    let addr = env::args().nth(1)
        .unwrap_or_else(|| "127.0.0.1:3000".to_string());

    let addr: SocketAddr = addr.parse().expect("invalid address");
    let listener = TcpListener::bind(&addr)
        .await
        .expect("invalid address");

    println!("listening on: {}", addr);
        
    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(handle_connection(stream));
    }
}
