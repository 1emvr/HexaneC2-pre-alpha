mod interface;

use hexlib::error::{ Result, Error };
use hexlib::types::{ ServerPacket, MessageType };

use crate::interface::{ init_print_channel, wrap_message, stop_print_channel };

use std::fs::File;
use std::io::{ self, Read, Write };

use tungstenite::{ connect, Message };
use tungstenite::handshake::server::Response as ServerResponse;
use tungstenite::Message::Text as Text;
use serde_json;

type WebSocketUpgrade = tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>; 

// TODO: options for payload build:
// 1. build locally with client. send configuration data up to the server.
// 2. build server-side and transmit payload back to the client

fn parse_packet(json: String) -> Result<()> {
	println!("server response: {:?}", json);
	Ok(())
}

fn read_json(target_path: &str) -> Result<String>{
	let mut read_data = Vec::new();
	let mut read_file = match File::open(target_path) {
		Ok(file) => file,
		Err(e) => {
			println!("json open error");
			return Err(Error::Custom("json open error: {e}".to_string()))
		}
	};

	match read_file.read_to_end(&mut read_data) {
		Ok(read) => read,
		Err(e) => {
			println!("json read error");
			return Err(Error::Custom("json read error: {e}".to_string()))
		}
	};

	/*

	let data = match str::from_utf8(read_data) {
		Ok(data) => data,
		Err(e) => {
			println!("string convert error");
			return Err(Error::Custom("string convert error".to_string()))
		}
	};
	 */

	Ok(String::from_utf8(read_data).unwrap())
}

fn parse_command(input: &str) -> Result<ServerPacket> {
	let split: Vec<&str> = input.split(" ").collect();

	let mut packet = ServerPacket {
		username: "lemur".to_string(),
		msg_type: MessageType::TypeCommand,
		buffer:   "".to_string(),
	};

	if split.len() >= 2 {
        if split[1] == "load" {

			packet.msg_type = MessageType::TypeConfig;
			packet.buffer = match read_json(split[2]) {
				Ok(json) => json,
				Err(e) => {
					return Err(Error::Custom("parse command failed".to_string()))
				}
			}
        }
    }
	else {
		packet.buffer = input.to_string();
	}

	Ok(packet)
}

fn send_packet(json: String, socket: &mut WebSocketUpgrade) -> Result<String> {
    match socket.write_message(Message::Text(json.clone())) {
		Ok(write) => (),
		Err(e) => {
			println!("[ERR] connection closed");
			return Err(Error::Custom("connection closed".to_string()))
		}
	}

    match socket.read_message() {
        Ok(Text(rsp)) => {
			println!("received response from server in json format");
			Ok(rsp)
		}
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

fn transmit_server(packet: ServerPacket, socket: &mut WebSocketUpgrade) -> Result<()> {
	println!("serializing ServerPacket");
	let server_packet = match serde_json::to_string(&packet) {
		Ok(json) => json,
		Err(e) => {
			wrap_message("ERR", format!("transmit_server: {e}").as_str());
			return Err(Error::Custom(e.to_string()))
		}
	};

	// TODO: hangs here when server fails to respond
	println!("sending ServerPacket");
	let rsp = match send_packet(server_packet, socket) {
		Ok(rsp) => rsp,
		Err(e) => {
			wrap_message("ERR", format!("transmit_server: {e}").as_str());
			return Err(Error::Custom(e.to_string()))
		}
	};

	println!("parsing response");
	if let Err(e) = parse_packet(rsp) {
		wrap_message("ERR", format!("transmit_server: {e}").as_str());
		return Err(Error::Custom(e.to_string()))
	}

	Ok(())
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

pub fn main() {
	init_print_channel();

    let url = std::env::args().nth(1)
		.unwrap_or_else(|| "ws://127.0.0.1:3000".to_string());

    let mut socket = match connect_server(url.as_str()) {
		Ok(socket) => socket,
		Err(e) => {
			wrap_message("ERR", "ws_session: {e}");
			return
		}
	};

	wrap_message("INF", format!("connected to {url}").as_str());

	loop {
		let mut input = String::new();
		println!("OK... ");

		io::stdout().flush().unwrap();
		io::stdin().read_line(&mut input).unwrap();

		let input = input.trim();
		if input.eq_ignore_ascii_case("exit") {
			break;
		}

		let packet = match parse_command(input) {
			Ok(packet) => packet,
			Err(e) => {
				continue;
			}
		};

		if let Err(e) = transmit_server(packet, &mut socket) {
			wrap_message("ERR", "packet send failed: {e}");
		};
	}

	socket.close(None).expect("failed to close WebSocket");
	stop_print_channel();
}
