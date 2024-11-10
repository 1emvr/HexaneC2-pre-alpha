use std::io::{self, Write};

use hexlib::stream::Stream;
use hexlib::error::{Result, Error};
use hexlib::types::{Hexane, HexaneStream, ServerPacket, MessageType, NetworkType};
use crate::interface::wrap_message;

use tungstenite::{connect, Message};
use tungstenite::handshake::server::Response as ServerResponse;
use tungstenite::Message::Text as Text;

use serde::ser::{Serialize, Serializer, SerializeStruct};
use serde_json;

type WebSocketUpgrade = tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>; 

// TODO: move to client data layer
fn parse_packet(rsp: String) {
    println!("[INF] reading json response");

    let parsed: Result<ServerPacket> = serde_json::from_str(&rsp)
		.expect("parse_packet: serde_json::from_str");

	match parsed {

		// NOTE: all messages are parsed server-side. The response data will be returned here.
        Ok(packet) => {
			match packet.msg_type {
				MessageType::TypeConfig => {
					println!("[INF] config updated");
				}
				MessageType::TypeCommand => {
					println!("[INF] command received");
				}
				MessageType::TypeTasking => {
					// TODO: update task counter and fetch user commands
					println!("[INF] task request recieved");
				}
				MessageType::TypeCheckin => {
					// TODO: print checkin information (hostname, username, ip, ETWTi if applicable, other...)
					println!("[INF] TypeCheckin: {:?}", packet.buffer);
				}
				MessageType::TypeResponse => {
					// TODO: print response data in json format.
					println!("[INF] response: {:?}", packet.buffer);
				}
				MessageType::TypeSegment => {
					// TODO: create buffers for fragmented packets. Print/store when re-constructed.
					println!("[INF] segmented message");
				}
				_ => {
					println!("[WRN] unhandled message type");
				}
			}
		}

        Err(e) => {
            println!("[ERR] server response is not valid JSON: {}", e);
            println!("[INF] server response: {}", rsp);
        }
    }
}

fn connect_server(url: &str) -> Result<WebSocketUpgrade> {
    match connect(url) {
        Ok((socket, _)) => Ok(socket),
        Err(e) => {
            println!("[ERR] error connecting to server");
            return Err(Error::Tungstenite(e))
        }
    }
}

fn send_server(json: String, socket: &mut WebSocketUpgrade) -> Result<String> {
    socket.write_message(Message::Text(json.clone()))
        .expect("[ERR] failed to send message");

    match socket.read_message() {
        Ok(Text(rsp)) => Ok(rsp),
        Ok(_) => {
			println!("[WRN] received non-JSON data from the server");
            Err(Error::Custom("invalid JSON".to_string()))
		}
        Err(e) => {
            println!("[ERR] error reading from server: {}", e);
            Err(Error::Tungstenite(e))
        }
    }
}

// TODO: send HexaneStream automatically on build
fn send_packet(packet: ServerPacket, socket: &mut WebSocketUpgrade) -> Result<()> {
	let server_packet = match serde_json::to_string(&packet) {
		Ok(json) => json,
		Err(e) => {
			wrap_message("ERR", format!("send_packet: {e}").as_str());
			return Err(Error::Custom(e.to_string()))
		}
	};

	let rsp = match send_server(server_packet, socket) {
		Ok(rsp) => {
			parse_packet(rsp);
		}
		Err(e) => {
			wrap_message("ERR", format!("send_packet: {e}").as_str());
			return Err(Error::Custom(e.to_string()))
		}
	};

	Ok(())
}

pub fn ws_update_config(instance: &Hexane) -> Result<()> {
	// TODO: all operations/interface should be server-side. the client should only handle ws connections
	// this will also reduce the amount of specific data types necessary to perform client-server communication

    let mut socket = match connect_server(instance.main_cfg.address) {
		Ok(socket) => socket,
		Err(e) => {
			wrap_message("ERR", format!("update_config: {e}").as_str());
			return Err(Error::Custom(e.to_string()))
		}
	};

	let config_stream = serde_json::to_string(&instance)
		.expect("Hexane serialization error");

	let packet = ServerPacket {
		peer_id:  123, // TODO: dynamically get peer id for implant
		msg_type: MessageType::TypeConfig,
		buffer:   config_stream 
	};

	if let Err(e) = send_packet(packet, &mut socket) {
		wrap_message("ERR", "update_config: {e}");
		return Err(Error::Custom(e.to_string()))
	};

	socket.close(None).expect("failed to close WebSocket");
	Ok(())
}

pub fn ws_interactive(url: String) {
    let mut socket = match connect_server(url.as_str()) {
		Ok(socket) => socket,
		Err(e) => {
			wrap_message("ERR", "ws_session: {e}");
			return
		}
	};

	wrap_message("INF", "connected to {url}");
	loop {
		let mut input = String::new();
		println!("> ");

		io::stdout().flush().unwrap();
		io::stdin().read_line(&mut input).unwrap();

		let input = input.trim();
		if input.eq_ignore_ascii_case("exit") {
			break;
		}

		// TODO: server-side command parsing
		let packet = ServerPacket {
			peer_id:  123, // TODO: dynamically get peer id for implant
			msg_type: MessageType::TypeCommand,
			buffer:   input.to_string()
		};

		if let Err(e) = send_packet(packet, &mut socket) {
			wrap_message("ERR", "packet send failed: {e}");
		};
	}

	socket.close(None).expect("failed to close WebSocket");
	wrap_message("INF", "main menu ->");
}
