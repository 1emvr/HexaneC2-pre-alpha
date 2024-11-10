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


fn send_packet(json: String, socket: &mut WebSocketUpgrade) -> Result<String> {
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
fn transmit_server(packet: ServerPacket, socket: &mut WebSocketUpgrade) -> Result<()> {
	let server_packet = match serde_json::to_string(&packet) {
		Ok(json) => json,
		Err(e) => {
			wrap_message("ERR", format!("transmit_server: {e}").as_str());
			return Err(Error::Custom(e.to_string()))
		}
	};

	let rsp = match send_packet(server_packet, socket) {
		Ok(rsp) => {
			parse_packet(rsp);
		}
		Err(e) => {
			wrap_message("ERR", format!("transmit_server: {e}").as_str());
			return Err(Error::Custom(e.to_string()))
		}
	};

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

pub fn ws_interactive(url: String) {
    let mut socket = match connect_server(url.as_str()) {
		Ok(socket) => socket,
		Err(e) => {
			wrap_message("ERR", "ws_session: {e}");
			return
		}
	};

	wrap_message("INF", format!("connected to {url}"));
	loop {
		let mut input = String::new();
		println!("> ");

		io::stdout().flush().unwrap();
		io::stdin().read_line(&mut input).unwrap();

		let input = input.trim();
		if input.eq_ignore_ascii_case("exit") {
			break;
		}

		let packet = ServerPacket {
			peer_id:  123,
			msg_type: MessageType::TypeCommand,
			buffer:   input.to_string()
		};

		if let Err(e) = transmit_server(packet, &mut socket) {
			wrap_message("ERR", "packet send failed: {e}");
		};
	}

	socket.close(None).expect("failed to close WebSocket");
	wrap_message("INF", "main menu ->");
}
