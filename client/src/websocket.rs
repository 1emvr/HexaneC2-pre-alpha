use tokio_tungstenite::connect_async;
use url::Url;

async fn listen_websocket() {
    let url = Url::parse("ws://your-aws-server-url/ws").unwrap();
    let (ws_stream, _) = connect_async(url).await.expect("failed to connect");

    while let Some(Ok(message)) = ws_stream.next().await {
        println!("Received: {:?}", message);
    }
}
