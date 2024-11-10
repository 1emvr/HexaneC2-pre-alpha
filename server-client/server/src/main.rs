mod data;

use std::env;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use serde_json::from_slice;
use futures::{StreamExt, SinkExt};
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio::net::{TcpListener, TcpStream};

use Message::Binary as Binary;
use Message::Close as Close;
use Message::Text as Text;

use hexlib::{ serialize_json, deserialize_json };
use hexlib::types::MessageType;

use crate::data::parse_config;


async fn process_packet(text: String) -> String {
    println!("[INF] processing message: {}", text);

	let des: ServerPacket = match serde_json::from_str::<ServerPacket>(text.as_str()) {
		Ok(des) => des,
		Err(e) => {
			return format!("[ERR] process_packet: invalid packet structure from user: {}", e);
		}
	}

	// TODO: parse buffer strings
}

async fn handle_connection(stream: TcpStream) {
    let ws_stream = match tokio_tungstenite::accept_async(stream).await {
        Ok(ws) => ws,
        Err(e) => {
            println!("[ERR] handle_connection: error during websocket handshake: {}", e);
            return
        }
    };

    let (mut sender, mut receiver) = ws_stream.split();

    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(Binary(_)) => {
                let rsp = process_packet(text).await;
                if let Err(e) = sender.send(Message::Text(rsp)).await {
					println!("[ERR] handle_connection: sending \"binary message\" message failed: {}", e);
				}
            },
            Ok(Text(text)) => {
                if let Err(e) = sender.send("INF TODO: json message").await {
                    println!("[ERR] handle_connection: sending \"json message\" message failed: {}", e);
                }
            },
            Ok(Close(_)) => {
				if let Err(e) = sender.send("[INF] handle_connection: TODO: close message").await {
					println!("[ERR] handle_connection: sending \"close connection\" message failed: {}", e);
				}
                break;
            },
            Err(e)=> {
                if let Err(e) = sender.send("[ERR] handle_connection: error processing message from user: {}", e).await {
					println!("[ERR] handle_connection: sending \"receive message\" message failed: {}", e);
				}
                break;
            }
            Ok(_) => {
                if let Err(e) = sender.send("[INF] handle_connection: TODO: unhandled message").await {
					println!("[ERR] handle_connection: sending \"invalid message\" message failed: {}", e);
				}
            },
        }
    }
}

#[tokio::main]
async fn main() {
    let addr = env::args()
		.nth(1)
		.unwrap_or_else(|| "ws://127.0.0.1:3000".to_string());

    let addr: SocketAddr = addr.parse()
		.expect("tokio::main: invalid address");

    let listener = TcpListener::bind(&addr)
		.await
		.expect("tokio::main: could not bind");

    println!("[INF] listening on: {}", addr);
    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(handle_connection(stream));
    }
}
