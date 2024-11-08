use std::io::{self, Write};

use hexlib::stream::Stream;
use hexlib::error::{Result, Error};
use hexlib::types::{HexaneStream, ServerPacket, MessageType, NetworkType};

use tungstenite::{connect, Message};
use tungstenite::handshake::server::Response as ServerResponse;
use tungstenite::Message::Text as Text;

use serde::ser::{Serialize, Serializer, SerializeStruct};
use serde_json;

type WebSocketUpgrade = tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>; 

fn parse_packet(rsp: String) {
    println!("[INF] reading json response");

    let parsed: Result<ServerPacket, _> = serde_json::from_str(&rsp);
	match parsed {

		// NOTE: all messages are parsed server-side. The response data will be returned here.
        Ok(packet) => {
			match packet.msg_type {
				MessageType::TypeConfig => {
					println!("[INF] config updated: {:?}", packet);
				}
				MessageType::TypeCommand => {
					println!("[INF] command received: {:?}", packet);
				}
				MessageType::TypeCheckin => {
					// TODO: print checkin information (hostname, username, ip, ETWTi if applicable, other...)
					println!("[INF] TypeCheckin: {:?}", packet);
				}
				MessageType::TypeTasking => {
					// TODO: update task counter and fetch user commands
					println!("[INF] TypeTasking: {:?}", packet);
				}
				MessageType::TypeResponse => {
					// TODO: print response data in json format.
					println!("[INF] TypeResponse: {:?}", packet);
				}
				MessageType::TypeSegment => {
					// TODO: create buffers for fragmented packets. Print/store when re-constructed.
					println!("[INF] TypeSegment: {:?}", packet);
				}
				_ => {
					println!("[WRN] unhandled message: {:?}", packet);
				}
			}
		}

        Err(e) => {
            println!("[ERR] server response is not valid JSON: {}", e);
            println!("[INF] server response: {}", rsp);
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

fn connect_server(url: &str) -> Result<WebSocketUpgrade> {
    match connect(url) {
        Ok((socket, _)) => Ok(socket),
        Err(e) => {
            println!("[ERR] error connecting to server");
            return Err(Error::Tungstenite(e))
        }
    };
}

pub fn ws_session(url: String) {
    let mut socket = match connect_server(url) {
		Ok(socket) => socket,
		Err(e) => {
			wrap_message("ERR", "cannot connect to server: {}", e);
			return
		}
	}

	wrap_message("INF connected to {}", url);
	loop {
		let mut input = String::new();
		io::stdout().flush().unwrap();

		println!("> ");

		stdin().read_line(&mut input).unwrap();
		let input = input.trim();

		if input.eq_ignore_ascii_case("exit") {
			break;
		}

		let args: Vec<String> = input.split_whitespace()
			.map(str::to_string)
			.collect();

		if args.is_empty() {
			continue;
		}
		
		let packet = match args[0].as_str() {
			"process" => {
				// TODO: process list, process modules, process migrate (pid)
				if args.len() != 2 {
					wrap_message("ERR", "process usage: list | modules | migrate <pid>");
					continue;
				}

				let command_data = args[0..].join(" ");

				// TODO: Valid commands need converted to TLV: (peer_id, task_id, msg_type, msg_length, [command data])
				// NOTE: Client provides peer_id and msg_type. Server provides task_id, command data/length
				ServerPacket {
					peer_id: 123,
					msg_type: MessageType::TypeCommand,
					buffer: command_data
				}
			},
			_ => {
				wrap_message("ERR", "invalid input");
				continue;
			}
		};

		let server_packet = match serde_json::to_string(&packet) {
			Ok(json) => json,
			Err(e) => {
				println!("[ERR] server packet serialization error: {}", e);
				return
			}
		};

		let rsp = match send_server(server_packet, &mut socket) {
			Ok(rsp) => {
				parse_packet(rsp);
			}
			Err(e) => {
				println!("[ERR] {}", e);
				continue;
			}
		}
	}

	wrap_message("INF", "main menu");
}
