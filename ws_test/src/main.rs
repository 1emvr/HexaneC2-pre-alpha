

async fn websocket_handler(ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket))
}

async fn handle_socket(mut socket: WebSocket) {
    while let Some(Ok(message)) = socket.recv().await {
        match message {
            Message::Text(body) => {
                println!("new message: {}", body);
            },
            Message::Close(_) => {
                println!("client disconnected");
            }
        }
    }
}

fn main() {

}
