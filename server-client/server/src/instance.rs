use std::fs;
use std::env;
use std::str::FromStr;
use std::sync::{ Arc, Mutex };

use bincode;
use rayon::prelude::*;

use hexlib::error::Result;
use hexlib::error::Error::Custom;
use hexlib::types::{Hexane, HexaneStream, ServerPacket, JsonData, UserSession};

use hexlib::types::NetworkType::Http as HttpType;
use hexlib::types::NetworkType::Smb as SmbType;
use hexlib::types::NetworkOptions::Http as HttpOpts;
use hexlib::types::NetworkOptions::Smb as SmbOpts;

use crate::interface::wrap_message;
use crate::builder::HexaneBuilder;
use crate::ws::ws_update_config;

use lazy_static::lazy_static;

lazy_static! {
    pub(crate) static ref INSTANCES: Arc<Mutex<Vec<Hexane>>> = Arc::new(Mutex::new(vec![]));
    pub(crate) static ref SESSION: Mutex<UserSession> = Mutex::new(UserSession {
        username: "".to_owned(),
        is_admin: false
    });
}

pub(crate) fn load_instance(args: Vec<&str>) -> String {
    if args.len() != 3 {
        "[ERR] invalid arguments"
    }

    let mut instance = match map_json_config(&args[2]) {
        Ok(instance) => instance,
        Err(e) => {
            return format!("[ERR] {e}")
        }
    };

    let name = instance.builder_cfg.output_name.clone();
    let mut instances = INSTANCES.lock().unwrap();

    if instances.iter()
        .any(|i| i.builder_cfg.output_name == name) {
            return format!("[ERR] config with name {} already exists", name)
        }

    if let Err(e) = instance.setup_build() {
        return format!("[ERR] {e}")
    }

    instances.push(instance);
    return format!("{} is ready", name)
}

pub(crate) fn remove_instance(args: Vec<&str>) -> String {
    if args.len() != 3 {
        return "invalid arguments"
    }

    let output_name = &args[2];
    let mut instances = match INSTANCES.lock() {
        Ok(instances) => instances,
        Err(_) => {
            return "instances could not be locked"
        }
    };

    if let Some(position) = instances.iter().position(|instance| instance.builder_cfg.output_name == *output_name) {
        instances.remove(position);
        return "instance removed"
    }
    else {
        return "implant not found"
    }
}

fn map_json_config(file_path: &str) -> Result<Hexane> {
	// TODO: sending json configs over the wire instead of using local files
    let curdir = env::current_dir()
        .map_err(|e| {
            format!("could not get current directory: {e}")
        });

    let json_file = curdir
        .unwrap()
        .join("json")
        .join(file_path);

    if !json_file.exists() {
        return Err("json file does not exist".to_string())
    }

    let contents = fs::read_to_string(json_file)
        .map_err(|e| format!("could not read json file: {e}"))?;

    let json_data = serde_json::from_str::<JsonData>(&contents)
        .map_err(|e| format!("could not parse json data: {e}"))?;

    let mut instance = Hexane::default();

    let config = json_data
		.map_err(|e| format!("map_json_config: {e}"))?;

    let session = SESSION.lock()
        .map_err(|e| format!("map_json_config: {e}"))?;

    instance.group_id       = 0;
    instance.main_cfg       = config.config;
    instance.loader_cfg     = config.loader;
    instance.builder_cfg    = config.builder;
    instance.network_cfg    = config.network;
    instance.user_session   = session.clone();

    Ok(instance)
}
