mod instance;
mod builder;
mod stream;
mod binary;
mod cipher;
mod utils;
mod types;
mod error;

use crate::instance::{ list_instances, load_instance, remove_instance };
use crate::types::ServerPacket;
use crate::utils::print_help;

use std::env;
use std::net::SocketAddr;
use std::sync::{ Arc, atomic::{ AtomicBool, Ordering }}; 

use tokio_tungstenite::tungstenite::protocol::Message;
use tokio::net::{ TcpListener, TcpStream };
use futures::{ StreamExt, SinkExt };

type SenderSink = SplitSink<WebSocketStream<TcpStream>, Message>;
type RecvStream = SplitStream<WebSocketStream<TcpStream>>;


struct WebSocketConnection {
	sender: SenderSink,
	receiver: RecvStream,
}

impl WebSocketConnection {
	async fn send(&mut self, msg: String) -> Result<()> {
		self.sender.send(Message::Text(msg)).await
	}

	async fn receive(&mut self) -> Option<Message> {
		self.receiver.next().await.transpose().ok().flatten()
	}
}


async fn interact_instance(ws_conn: &mut WebSocketConnection, args: Vec<&str>) {
// TODO: implement and move to instance.rs
}

async fn parse_command(ws_conn: &mut WebSocketConnection, buffer: String, exit_flag: Arc<AtomicBool>) {
	let args: Vec<&str> = buffer.split_whitespace().collect();

	println!("[INF] matching arguments");
	match args[0] {
		"help" => ws_conn.send(Message::Text(print_help())).await.unwrap_or_default(),

		"implant" => {
			if args.len() < 2 {
				ws_conn.send(Message::Text("[ERR] invalid input")).await.unwrap_or_default();
				return
			}
			match args[1] {
				"ls"   => list_instances(ws_conn.sender).await,
				"load" => load_instance(ws_conn.sender, args).await,
				"rm"   => remove_instance(ws_conn.sender, args).await,
				"i"    => interact_instance(ws_conn, args).await,
				_ => {
					ws_conn.sender.send(Message::Text("[ERR] invalid input")).await.unwrap_or_default(),
				}
			}
		},

		"exit" => {
			ws_conn.send(Message::Text("[INF] exiting...")).await.unwrap_or_default();
			exit_flag.store(true, Ordering::Relaxed);
		}
		_ => {
			ws_conn.sender.send(Message::Text("[ERR] invalid input")).await.unwrap_or_default();
		}
	}
}

async fn process_packet(ws_conn: &mut WebSocketConnection, msg: String, exit_flag: Arc<AtomicBool>) {
	println!("[DBG] processing packet");

	let des: ServerPacket = match serde_json::from_str::<ServerPacket>(msg.as_str()) {
		Ok(des) => des,
		Err(e) => {
			println!("[ERR] process_packet: invalid packet structure from user: {}", e);
			return format!("[ERR] process_packet: invalid packet structure from user: {}", e)
		}
	};

	match des.msg_type {
		MessageType::TypeCommand => parse_command(ws_conn, des.buffer, exit_flag).await,
		MessageType::TypeConfig => parse_config(ws_conn, des.buffer).await,
		_ => {
			ws_conn.sender.send(Message::Text("[ERR] invalid input")).await
		}
	}
}

async fn handle_connection(stream: TcpStream, exit_flag Arc<AtomicBool>) {
    let ws_stream = match tokio_tungstenite::accept_async(stream).await {
        Ok(ws) => ws,
        Err(e) => {
            println!("[ERR] error during websocket handshake: {}", e);
            return
        }
    };

    let (mut sender, mut receiver) = ws_stream.split();
	let mut ws_conn = WebSocketConnection { sender, receiver };

    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(Message::Text(msg)) => {
				println!("[DBG] incoming json message from client");
                let rsp = process_packet(ws_conn, msg, exit_flag).await;
            },
            Ok(Message::Close(_)) => {
				println!("[DBG] closing client websocket");
				if let Err(e) = sender.send(Message::Text("closing...".to_string())).await {
					println!("[ERR] handle_connection: sending \"close connection\" message failed: {}", e);
				}

                break;
            },
            Err(e)=> {
				println!("[DBG] error parsing message from client");
                if let Err(e) = sender.send(Message::Text(format!("{}", e))).await {
					println!("[ERR] handle_connection: sending \"receive message\" message failed: {}", e);
				}
            }
			_ => continue;
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
		let (stream, _) = listener.accept().await {
			Ok(conn) => conn,
			Err(e) => {
				println!("[ERR] failed to accept connection: {}", e);
				continue;
			}
		}

		let exit_flag = arc_exit.clone();
		tokio::spawn(async move {
			handle_connection(stream, exit_flag).await;
		});

		if arc_exit.load(Ordering::Relaxed) {
			println!("[INF] client closed. Resuming listener...");
		}
	}
}
