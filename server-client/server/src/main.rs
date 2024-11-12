mod instance;
mod builder;
mod stream;
mod binary;
mod cipher;
mod utils;
mod types;
mod error;

use crate::utils::print_help;
use crate::types::{ MessageType, ServerPacket, WebSocketConnection };
use crate::instance::{
	list_instances,
	load_instance,
	remove_instance,
	interact_instance
};

use std::env;
use std::net::SocketAddr;
use std::sync::{ Arc, atomic::{ AtomicBool, Ordering }}; 

use futures::StreamExt;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio::net::{ TcpListener, TcpStream };


async fn parse_config(ws_conn: &mut WebSocketConnection, buffer: String) {
	// TODO: parse and store hexane json
}

async fn parse_command(ws_conn: &mut WebSocketConnection, buffer: String, exit_flag: Arc<AtomicBool>) {
	let args: Vec<&str> = buffer.split_whitespace().collect();

	println!("[INF] matching arguments");
	match args[0] {

		"help" => ws_conn.send(print_help()).await.unwrap_or_default(),
		"implant" => {

			if args.len() < 2 {
				ws_conn.send("[ERR] invalid input".to_string()).await.unwrap_or_default();
				return
			}

			match args[1] {
				"ls"   => list_instances(ws_conn).await,
				"load" => load_instance(ws_conn, args).await,
				"rm"   => remove_instance(ws_conn, args).await,
				"i"    => interact_instance(ws_conn, args).await,
				_ => {
					ws_conn.send("[ERR] invalid input".to_string()).await.unwrap_or_default();
				}
			}
		},

		"exit" => {
			ws_conn.send("[INF] exiting...".to_string()).await.unwrap_or_default();
			exit_flag.store(true, Ordering::Relaxed);
		}
		_ => {
			ws_conn.send("[ERR] invalid input".to_string()).await.unwrap_or_default();
		}
	}
}

async fn process_packet(ws_conn: &mut WebSocketConnection, msg: String, exit_flag: Arc<AtomicBool>) {
	println!("[DBG] processing packet");
	/*
	ServerPacket { MessageType::TypeCommand, "lemur", "implant load {json buffer}"}
	 */

	let des: ServerPacket = match serde_json::from_str::<ServerPacket>(msg.as_str()) {
		Ok(des) => des,
		Err(e) => {
			ws_conn.send(format!("[ERR] process_packet: invalid packet structure from user: {}", e));
			return
		}
	};

	match des.msg_type {
		MessageType::TypeCommand => parse_command(ws_conn, des.buffer, exit_flag).await,
		MessageType::TypeConfig => parse_config(ws_conn, des.buffer).await,
		_ => {
			let _ = ws_conn.send("[ERR] invalid input".to_string()).await;
			return
		}
	}
}

async fn handle_connection(stream: TcpStream, exit_flag: Arc<AtomicBool>) {
    let ws_stream = match tokio_tungstenite::accept_async(stream).await {
        Ok(ws) => ws,
        Err(e) => {
            println!("[ERR] error during websocket handshake: {}", e);
            return
        }
    };

    let (mut sender, mut receiver) = ws_stream.split();
	let mut ws_conn = WebSocketConnection { sender, receiver };

    while let Some(msg) = ws_conn.receiver.next().await {
        match msg {
            Ok(Message::Text(msg)) => {
				println!("[DBG] incoming json message from client");
                process_packet(&mut ws_conn, msg, exit_flag.clone()).await;
            },
            Ok(Message::Close(_)) => {
				println!("[DBG] closing client websocket");
                break;
            },
            Err(e)=> {
				println!("[DBG] error parsing message from client: {}", e);
            }
			_ => continue,
        }

		if exit_flag.load(Ordering::Relaxed) {
			println!("[INF] resetting closed connection");
			break;
		}
    }
}

#[tokio::main]
async fn main() {
    let addr = env::args().nth(1)
		.unwrap_or_else(|| "127.0.0.1:3000".to_string());

    let addr: SocketAddr = addr.parse()
		.expect("tokio::main: invalid address");

    let listener = TcpListener::bind(&addr).await
		.expect("tokio::main: could not bind");

	let arc_exit = Arc::new(AtomicBool::new(false));

    println!("[INF] listening on: {}", addr);

	loop {
		let (stream, _) = match listener.accept().await {
			Ok(conn) => conn,
			Err(e) => {
				println!("[ERR] failed to accept connection: {}", e);
				continue;
			}
		};

		let exit_flag = arc_exit.clone();
		tokio::spawn(async move {
			handle_connection(stream, exit_flag).await;
		});

		if arc_exit.load(Ordering::Relaxed) {
			println!("[INF] client closed. Resuming listener...");
		}
	}
}
