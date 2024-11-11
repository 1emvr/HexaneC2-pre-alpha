mod instance;
mod builder;
mod stream;
mod binary;
mod cipher;
mod utils;
mod types;
mod error;

use std::env;
use std::net::SocketAddr;

use tokio_tungstenite::tungstenite::protocol::Message;
use tokio::net::{ TcpListener, TcpStream };
use futures::{ StreamExt, SinkExt };

use crate::instance::{ list_instances, load_instance, remove_instance };
use crate::types::ServerPacket;


async fn process_packet(msg: Vec<u8>) -> String {
	let text: &str = match std::str::from_utf8(&msg) {

		Ok(text) => text,
		Err(e) => {
			return format!("[ERR] process_packet: error converting binary to utf8: {}", e)
		}
	};

	let des: ServerPacket = match serde_json::from_str::<ServerPacket>(text) {
		Ok(des) => des,
		Err(e) => {
			return format!("[ERR] process_packet: invalid packet structure from user: {}", e)
		}
	};

	let args: Vec<&str> = des.buffer
		.split_whitespace()
		.collect();

	match args[0] {
		"exit" => return "[INF] exiting...".to_string(),
		"help" => crate::utils::print_help(),

		// TODO: test that these at least work
		"implant" => {
			match args[1] {
				"ls"   => list_instances(),
				"load" => load_instance(args),
				"rm"   => remove_instance(args),
				_      => return "[ERR] invalid input".to_string(),
	        }
	    }
		_ => return "[ERR] invalid input".to_string()
	}
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
            Ok(Message::Binary(msg)) => {
                let rsp = process_packet(msg).await;
                if let Err(e) = sender.send(Message::Text(rsp)).await {
					println!("[ERR] handle_connection: sending \"binary message\" message failed: {}", e);
				}
            },
            Ok(Message::Text(_msg)) => {
                if let Err(e) = sender.send(Message::Text("json txt".to_string())).await {
                    println!("[ERR] handle_connection: sending \"json message\" message failed: {}", e);
                }
            },
            Ok(Message::Close(_)) => {
				if let Err(e) = sender.send(Message::Text("closing...".to_string())).await {
					println!("[ERR] handle_connection: sending \"close connection\" message failed: {}", e);
				}
                break;
            },
            Err(e)=> {
                if let Err(e) = sender.send(Message::Text(format!("{}", e))).await {
					println!("[ERR] handle_connection: sending \"receive message\" message failed: {}", e);
				}
                break;
            }
            Ok(_) => {
                if let Err(e) = sender.send(Message::Text("unhandled message".to_string())).await {
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
		.unwrap_or_else(|| "127.0.0.1:3000".to_string());

    let addr: SocketAddr = addr.parse()
		.expect("tokio::main: invalid address");

    let listener = TcpListener::bind(&addr).await
		.expect("tokio::main: could not bind");

    println!("[INF] listening on: {}", addr);
    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(handle_connection(stream));
    }
}
