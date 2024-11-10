mod data;

use std::env;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use serde_json::from_slice;
use futures::{StreamExt, SinkExt};
use tokio_tungstenite::{accept_async, tungstenite::protocol::Message};
use tokio::net::{TcpListener, TcpStream};

use hexlib::{ serialize_json, deserialize_json };
use hexlib::types::MessageType;

use crate::data::parse_config;


async fn process_message(text: String) -> String {
    println!("[INF] processing message: {}", text);

	let des: ServerPacket = match serde_json::from_str::<ServerPacket>(text.as_str()) {
		Ok(des) => des,
		Err(e) => {
			return format!("[ERR] invalid packet structure from user: {}", e)
		}
	}

    match des.msg_type {

        TypeConfig => {
            let rsp = parse_config(des.buffer).await;
            return rsp;
        }
		TypeCommand => {
			// TODO: parse command to TLV and queue per implant peer_id
			return "[INF] command was processed".to_string();
		}
        _ => {
            return "[ERR] process_message: unknown user message type".to_string();
        }
    }
}

async fn handle_connection(stream: TcpStream) {
    let ws_stream = match accept_async(stream).await {
        Ok(ws) => ws,
        Err(e) => {
            println!("[ERR] handle_connection: error during websocket handshake: {}", e);
            return
        }
    };

	println!("[INF] ws handshake successful");

    let (mut sender, mut receiver) = ws_stream.split();
    while let Some(msg) = receiver.next().await {
        match msg {

            Ok(Message::Text(text)) => {
                let rsp = process_message(text).await;
                if let Err(e) = sender.send(Message::Text(rsp)).await {
                    println!("[ERR] handle_connection: error sending message to user: {}", e);
                }
            },
            Ok(Message::Close(_)) => {
				if let Err(e) = sender.send("[INF] handle_connection: user closing connection").await {
					println!("[ERR] handle_connection: sending \"close connection\" message failed: {}", e);
				}
                break;
            },
            Ok(Message::Binary(_)) => {
                if let Err(e) = sender.send("[INF] handle_connection: binary message from user. Ignoring...").await {
					println!("[ERR] handle_connection: sending \"binary message\" message failed: {}", e);
				}
            },
            Ok(_) => {
                if let Err(e) = sender.send("[INF] handle_connection: unknown message type from user. Ignoring...").await {
					println!("[ERR] handle_connection: sending \"invalid message\" message failed: {}", e);
				}
            },
            Err(e)=> {
                if let Err(e) = sender.send("[ERR] handle_connection: error processing message from user: {}", e).await {
					println!("[ERR] handle_connection: sending \"receive message\" message failed: {}", e);
				}
                break;
            }
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
