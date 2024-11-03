use url::Url;
use std::io::{self, Write};

use tungstenite::{connect, Message};
use tungstenite::Message::Text as Text;

use serde::ser::{Serialize, Serializer, SerializeStruct};
use serde_json;

use hexlib::stream::Stream;
use hexlib::types::{HexaneStream, MessageType, NetworkType};

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

fn parse_binary() {
    println!("[INF] non-text server response. Not printing...");
}

fn main() {
    let (mut socket, _response) = connect(Url::parse("ws://127.0.0.1:3000").unwrap())
        .expect("[ERR] error connecting to server");

    loop {
        println!("> ");
        let mut input = String::new();

        io::stdout().flush()
            .expect("[ERR] fatal: cannot flush stdout");

        io::stdin().read_line(&mut input)
            .expect("[ERR] fatal: cannot read stdin");

        let args = input.trim().to_string();
        if args.to_lowercase() == "exit" {
            break;
        }

	    socket.write_message(Message::Text(args.clone()))
            .expect("[ERR] failed to send message");

        match socket.read_message() {
            Ok(_) => parse_binary(rsp),
            Ok(Text(rsp)) => parse_json(rsp),
            Err(e) => {
                println!("[ERR] error reading from server: {}", e);
                break;
            }
        }
    }
}
