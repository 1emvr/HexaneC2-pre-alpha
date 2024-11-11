use crate::error::Result;
use crate::types::{ Hexane, JsonData, UserSession };

use std::sync::{ Arc, Mutex };
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
        return "[ERR] invalid arguments".to_string()
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
        return "invalid arguments".to_string()
    }

    let output_name = &args[2];
    let mut instances = match INSTANCES.lock() {
        Ok(instances) => instances,
        Err(_) => {
            return "instances could not be locked".to_string()
        }
    };

    if let Some(position) = instances.iter().position(|instance| instance.builder_cfg.output_name == *output_name) {
        instances.remove(position);
        return "instance removed".to_string()
    }
    else {
        return "implant not found".to_string()
    }
}

pub(crate) fn list_instances() -> String {
	// TODO: serialize instance data and return to the client
	return "[INF] TODO: implement list_instances()".to_string()
}

fn map_json_config(contents: &str) -> Result<Hexane> {
	// TODO: sending json configs over the wire instead of using local files
    let config = serde_json::from_str::<JsonData>(&contents)
        .map_err(|e| format!("could not parse json data: {e}"))?;

    let mut instance = Hexane::default();

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
