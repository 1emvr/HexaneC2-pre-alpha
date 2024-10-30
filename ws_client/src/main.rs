use std::env;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use futures_util::{future, pin_mut, StreamExt};
use futures;

async fn read_stdin(tx: futures_channel::mpsc::UnboundedSender<Message>) {
    let mut stdin = tokio::io::stdin();
    loop {
        let mut buffer = vec![0; 1024];
        let n = match stdin.read(&mut buffer).await {
            Ok(n) => n,
            Ok(0) | Err(_) => break,
        };

        buffer.truncate(n);
        tx.unbounded_send(Message::binary(buffer)).unwrap();
    }
}

#[tokio::main]
async fn main() {
    let url = env::args().nth(1)
        .unwrap_or_else(|| panic!("usage: ws_client <url>"));

    let (stdin_tx, stdin_rx) = futures::channel::mpsc::unbounded();
    tokio::spawn(read_stdin(stdin_tx));

    let (ws, _) = connect_async(&url).await
        .expect("failed to connect");

    println!("websocket handshake successful");
    let (write, read) = ws.split();

    let stdin_to_ws = stdin_rx.map(Ok).forward(write);
    let ws_to_stdout = {

        read.for_each(|message| async {
            let data = message.unwrap().into_data();

            tokio::io::stdout()
                .write_all(&data)
                .await
                .unwrap();
        })
    };

    pin_mut!(stdin_to_ws, ws_to_stdout); 
    future::select(stdin_to_ws, ws_to_stdout).await;
}
