use std::fs;
use std::env;
use std::str::FromStr;
use rayon::prelude::*;

use crate::types::Hexane;
use crate::types::JsonData;
use crate::rstatic::{INSTANCES, SESSION};

use crate::error::Result;
use crate::error::Error::Custom;
use crate::interface::wrap_message;

pub(crate) fn load_instance(args: Vec<String>) {
    if args.len() != 3 {
        wrap_message("error", "invalid arguments");
        return
    }

    wrap_message("info", "loading instance");

    let session = SESSION.lock().unwrap();
    let mut instance = map_json_config(&args[2]).unwrap();


    wrap_message("info", "setting session");
    instance.user_session.username = session.username.clone();
    instance.user_session.is_admin = session.is_admin.clone();

    wrap_message("info", "setting up build");
    instance.setup_build();

    wrap_message("info", format!("{} is ready", instance.builder_cfg.output_name).as_str());
    INSTANCES.lock().unwrap().push(instance);
}

pub(crate) fn remove_instance(args: Vec<String>) {
    if args.len() < 2 {
        wrap_message("error", "invalid arguments");
        return
    }

    let mut instances = INSTANCES.lock().unwrap();
    if let Some(select) = instances
        .iter()
        .position(
            |instance| instance.builder_cfg.output_name == args[2]) {

        wrap_message("info", format!("removing {}", instances[select].builder_cfg.output_name).as_str());
        instances.remove(select);

    }
    else {
        wrap_message("error", "Implant not found");
        return
    }
}

pub(crate) fn interact_instance(args: Vec<String>) {
    // todo: implement
    return
}

fn map_json_config(file_path: &String) -> Result<Hexane> {
    wrap_message("info", "loading json");

    let json_file = env::current_dir()
        .unwrap()
        .join("json")
        .join(file_path);


    wrap_message("info", "creating json path");
    if !json_file.exists() {
        wrap_message("error", "json file does not exist");
        return Err(Custom("fuck you".to_string()))
    }


    wrap_message("info", "reading json content");
    let contents = fs::read_to_string(json_file)
        .unwrap();

    if contents.is_empty() {
        wrap_message("error", "json doesn't seem to exist");
        return Err(Custom("fuck you".to_string()))
    }

    wrap_message("info", "parsing json data");
    let json_data = serde_json::from_str::<JsonData>(&contents).unwrap();

    wrap_message("info", "setting instance data");
    let mut instance    = Hexane::default();
    let session         = SESSION.lock()?;

    instance.group_id       = 0;
    instance.main_cfg       = json_data.config;
    instance.loader_cfg     = json_data.loader;
    instance.builder_cfg    = json_data.builder;
    instance.network_cfg    = json_data.network;
    instance.user_session   = session.clone();

    Ok(instance)
}
