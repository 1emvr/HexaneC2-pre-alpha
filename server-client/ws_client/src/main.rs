use tokio::net::TcpStream;
use tokio::io::{self, AsyncWriteExt};
use serde::ser::{Serialize, Serializer, SerializeStruct};
use serde_json;

use hexlib::stream::Stream;
use hexlib::types::{Hexane, MessageType};


#[tokio::main]
async fn main() -> io::Result<()> {
    let data = Hexane {
        taskid: 1,
        peer_id: 1234,
        group_id: 4321,
        build_type: 1,
        session_key: vec![1, 2, 3, 4],
        shellcode: vec![5, 6, 7, 8],
        config: vec![9, 10, 11, 12],
        active: true,
        main_cfg: Default::default(),
        builder_cfg: Default::default(),
        compiler_cfg: Default::default(),
        network_cfg: None,
        loader_cfg: None,
        user_session: Default::default(),
    };

    let serial = serde_json::to_vec(&data)
        .expect("failed to serialize hexane");

    let mut stream = Stream::new();

    let peer_id = 1234;
    let task_id = 1;
    let msg_length = serial.len() as u32;

    stream.create_header(peer_id, task_id, MessageType::TypeConfig as u32);
    stream.pack_uint32(msg_length);
    stream.pack_bytes(&serial);

    let mut socket = TcpStream::connect("127.0.0.1:3000").await?;
    println!("connected to server");

    socket.write_all(stream.get_buffer()).await?;
    println!("data sent to server");

    Ok(())
}
