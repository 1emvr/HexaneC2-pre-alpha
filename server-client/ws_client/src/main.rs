use url::Url;
use tungstenite::{connect, Message};

use serde::ser::{Serialize, Serializer, SerializeStruct};
use serde_json;

use hexlib::stream::Stream;
use hexlib::types::{HexaneStream, MessageType, NetworkType};

fn main() {
	let (mut socket, response) = connect(Url::parse("ws://127.0.0.1:3000").unwrap())
		.expect("cannot connect");

	socket.write_message(Message::Text("hello, ws_server".into()))
		.unwrap();

	loop {
		let msg = socket.read_message().expect("error reading message");
		let msg = match msg {
			tungstenite::Message::Text(s) => s,
			_ => panic!()
		};

		let parsed: serde_json::Value = serde_json::from_str(&msg)
			.expect("cannot parse server response");

		println!("{:?}", parsed["result"]);
	}
}