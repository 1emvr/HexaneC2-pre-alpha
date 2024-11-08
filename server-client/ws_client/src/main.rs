use url::Url;
use std::io::{self, Write};

use hexlib::stream::Stream;
use hexlib::error::{Result, Error};
use hexlib::types::{HexaneStream, ServerPacket, MessageType, NetworkType};
use hexlib::{json_serialize, json_deserialize};

use tungstenite::{connect, Message};
use tungstenite::handshake::server::Response as ServerResponse;
use tungstenite::Message::Text as Text;

use serde::ser::{Serialize, Serializer, SerializeStruct};
use serde_json;

type WebSocketUpgrade = tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>; 


fn parse_json(rsp: String) {
    println!("[INF] reading json response");

    let parsed: Option<serde_json::Value> = match serde_json::from_str(&rsp) {
        Ok(parsed) => parsed,
        Err(_) => {
            println!("[ERR] server response is not valid JSON");
            None
        }
    };

    if let Some(json) = parsed {
        println!("{:?}", json["result"]);
    }
}

fn write_server(json: String, socket: &mut WebSocketUpgrade) -> Result<()> {
    socket.write_message(Message::Text(json.clone()))
        .expect("[ERR] failed to send message");

    match socket.read_message() {
        Ok(_) => println!("[WRN] received non-JSON data from the server"),

        Ok(Text(rsp)) => parse_json(rsp),
        Err(e) => {
            println!("[ERR] error reading from server: {}", e);
            return Err(Error::Tungstenite(e))
        }
    }

    Ok(())
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
    let cfg_json = match json_serialize(config) {
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
	let json_packet = match json_serialize(packet) {
		Ok(json) => json,
		Err(e) => {
			println!("[ERR] packet serialization error: {}", e);
			return
		}
	};

	println!("[INF] sending to server");
    write_server(json_packet, &mut socket);

	println!("[INF] complete");
}
