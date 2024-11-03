use url::Url;
use std::io::{self, Write};

use hexlib::stream::Stream;
use hexlib::types::{HexaneStream, MessageType, NetworkType};
use hexlib::error::{Result, Error};

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

fn serialize_hexane() -> Result<String> {
    let data = HexaneStream {
        peer_id:       123,
        group_id:      321,
        username:      "lemur".to_string(),
        session_key:   vec![1,2,3,4,5,6,7,8],
        endpoints:     vec!["/bullshit".to_string()],
        network_type:  NetworkType::Http,
    };

    let json = match serde_json::to_string(&data) {
        Ok(json) => json,
        Err(e) => {
            println!("failed to serialize hexane stream to JSON");
            return Err(Error::SerdeJson(e))
        }
    };

    Ok(json)
}

fn main() {
    let url = "ws://127.0.0.1:3000";
    let mut socket = connect_server(url)
        .expect("cannot connect");

    let json = match serialize_hexane() {
        Ok(json) => json,
        Err(_) => return
    };

    write_server(json, &mut socket);
}
