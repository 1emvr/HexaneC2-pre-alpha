mod types;
mod parser;
mod stream;
mod error;

use crate::error::{Error, Result};

use log::info;
use std::{env, io::Error};
use tokio::net::{TcpListener, TcpStream};

async fn accept_connection(stream: TcpStream) {
    let addr = stream.peer_addr()
        .expect("connected streams should have a peer address");

    println!("client address: {}", addr);
    let ws = tokio_tungstenite::accept_async(stream)
        .await
        .expect("error during websocket handshake");

    println!("websocket connection successful");

    let (write, read) = ws.split();
    read.try_filter(|msg| future::ready(msg.is_text() || msg.is_binary()))
        .forward()
        .await
        .expect("failed to forward message");

    println!("server write successful");
}


#[tokio::main]
async fn main() -> Result<()> {
    let addr = env::args().nth(1)
        .unwrap_or_else(|| "127.0.0.1:3000".to_string());

    let socket = TcpListener::bind(&addr).await;
    let listener = socket.expect("failed to bind");

    println!("listening on: {}", addr);

    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(accept_connection(stream));
    }

    Ok(())
}

