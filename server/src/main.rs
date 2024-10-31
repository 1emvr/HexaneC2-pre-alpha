mod types;
mod parser;
mod stream;
mod error;

use std::env;
use std::net::SocketAddr;
use log::{info, error};

use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{accept_async, tungstenite::protocol::Message};
use futures::{StreamExt, SinkExt};

// NOTE: client/server messaging
// TODO: http_server/implant messaging
async fn process_message(text: String) -> String {

    // TODO: process message by type, starting with MessageType::TypeConfig
    // deserialize stream object with Parser
    let parser = CreateParser(text.into_bytes());

    // peer_id, task_id, msg_type, msg_length, [buffer]
    // should I nest implant commands and use peer_id as "user_id" instead?
    // for example, first frame is operator information, second frame is implant/command data
}

async fn handle_connection(stream: TcpStream) {
    let ws_stream = match accept_async(stream).await {
        Ok(ws) => ws,
        Err(e) => {
            error!("error during websocket handshake: {}", e);
            return
        }
    };

    let (mut sender, mut receiver) = ws_stream.split();
    while let Some(msg) = receiver.next().await {
        match msg {

            Ok(_) => (),
            Ok(Message::Text(text)) => { // String
                let resp = process_message(text);


                if let Err(e) = sender.send(response).await {
                    error!("error sending message: {}", e);
                }
            }
            Ok(Message::Close(_)) => {
                info!("client closing connection");
                break;
            };
            Err(e)=> {
                error!("error processing message: {}", e);
                break;
            }
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let addr = env::args().nth(1).unwrap_or_else(|| "127.0.0.1:3000".to_string());
    let addr: SocketAddr = addr.parse().expect("invalid address");

    let listener = TcpListener::bind(&addr).await.expect("could not bind");
    info!("listening on: {}", addr);

    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(handle_connection(stream));
    }
}
