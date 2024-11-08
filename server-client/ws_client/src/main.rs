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
					println!("[INF] config updated: {:?}", packet.buffer);
				}
				MessageType::TypeCommand => {
					println!("[INF] command received: {:?}", packet.buffer);
				}
				MessageType::TypeCheckin => {
					// TODO: print checkin information (hostname, username, ip, ETWTi if applicable, other...)
					println!("[INF] TypeCheckin: {:?}", packet.buffer);
				}
				MessageType::TypeTasking => {
					// TODO: update task counter and fetch user commands
					println!("[INF] TypeTasking: {:?}", packet.buffer);
				}
				MessageType::TypeResponse => {
					// TODO: print response data in json format.
					println!("[INF] TypeResponse: {:?}", packet.buffer);
				}
				MessageType::TypeSegment => {
					// TODO: create buffers for fragmented packets. Print/store when re-constructed.
					println!("[INF] TypeSegment: {:?}", packet.buffer);
				}
				_ => {
					println!("[WRN] unhandled message type: {:?}", packet.msg_type);
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
			println!("[WRN] received non-JSON data from the server: {}", rsp),
            Err(Error::Custom("invalid JSON".to_string()))
		}
        Err(e) => {
            println!("[ERR] error reading from server: {}", e);
            Err(Error::Tungstenite(e))
        }
    }
}

fn connect_server(url: &str) -> Result<WebSocketUpgrade> {
    let (mut socket, _rsp) = match connect(url) {
        Ok(ok) => ok,
        Err(e) => {
            println!("[ERR] error connecting to server");
            return Err(Error::Tungstenite(e))
        }
    };

    Ok(socket)

}

fn main() {
    let url = "ws://127.0.0.1:3000";
    let mut socket = connect_server(url)
        .expect("[ERR] cannot connect");

	println!("[INF] connected to server");
    let config = HexaneStream {
        peer_id:       123,
        group_id:      321,
        username:      "lemur".to_string(),
        session_key:   vec![1,2,3,4,5,6,7,8],
        endpoints:     vec!["/bullshit".to_string()],
        network_type:  NetworkType::Http,
    };

	println!("[INF] serializing config");
    let cfg_json = match serde_json::to_string(&config) {
        Ok(json) => json,
        Err(e) => {
            println!("[ERR] config serialization error: {}", e);
            return
        }
    };

	let packet = ServerPacket {
		peer_id: 1,
		msg_type: MessageType::TypeConfig,
		buffer: cfg_json,
	};

	println!("[INF] serializing packet");
	let json_packet = match serde_json::to_string(&packet) {
		Ok(json) => json,
		Err(e) => {
			println!("[ERR] packet serialization error: {}", e);
			return
		}
	};

	println!("[INF] sending to server");
    let rsp = match send_server(json_packet, &mut socket) {
		Ok(rsp) => {
			// TODO: unwrap ServerPacket
			parse_packet(rsp);
		}
	}

	println!("[INF] complete");
}
