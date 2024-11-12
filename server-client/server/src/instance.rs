use crate::error::Result;
use crate::types::{ Hexane, JsonData, UserSession, WebSocketConnection };

use std::sync::Arc;
use tokio::sync::Mutex;
use lazy_static::lazy_static;

lazy_static! {

    pub(crate) static ref INSTANCES: Arc<Mutex<Vec<Hexane>>> = Arc::new(Mutex::new(vec![]));
    pub(crate) static ref SESSION: Mutex<UserSession> = Mutex::new(UserSession {
        username: "".to_owned(),
        is_admin: false
    });
}

pub(crate) async fn load_instance(ws_conn: &mut WebSocketConnection, config: String) {
    let mut instance = match map_json_config(config).await {
        Ok(instance) => instance,
        Err(e) => {
            ws_conn.send(format!("[ERR] {}", e)).await;
			return
        }
    };

    let name = instance.builder_cfg.output_name.clone();
    let mut instances = INSTANCES.lock().await;

    if instances.iter()
        .any(|i| i.builder_cfg.output_name == name) {
            ws_conn.send(format!("[ERR] config with name {} already exists", name)).await;
			return
        }

    if let Err(e) = instance.setup_build() {
        ws_conn.send(format!("[ERR] {}", e)).await;
		return
    }

    instances.push(instance);
    ws_conn.send(format!("{} is ready", name)).await;
}

pub(crate) async fn interact_instance(ws_conn: &mut WebSocketConnection, args: Vec<&str>) {
	ws_conn.send("[INF] implement interact_instance".to_string()).await;
}

pub(crate) async fn remove_instance(ws_conn: &mut WebSocketConnection, args: Vec<&str>) {
    if args.len() != 3 {
        ws_conn.send("invalid arguments".to_string()).await;
		return
    }

    let output_name = &args[2];
    let mut instances = INSTANCES.lock().await;

    if let Some(position) = instances.iter().position(|instance| instance.builder_cfg.output_name == *output_name) {
        instances.remove(position);
        ws_conn.send("instance removed".to_string()).await;
		return
    }

	ws_conn.send("implant not found".to_string()).await;
}

pub(crate) async fn list_instances(ws_conn: &mut WebSocketConnection) {
	ws_conn.send("[INF] TODO: implement list_instances()".to_string()).await;
}

async fn map_json_config(contents: String) -> Result<Hexane> {
    let config = serde_json::from_str::<JsonData>(&contents)
        .map_err(|e| format!("could not parse json data: {e}"))?;

    let mut instance = Hexane::default();
    let session = SESSION.lock().await;

    instance.group_id       = 0;
    instance.main_cfg       = config.config;
    instance.loader_cfg     = config.loader;
    instance.builder_cfg    = config.builder;
    instance.network_cfg    = config.network;
    instance.user_session   = session.clone();

    Ok(instance)
}

