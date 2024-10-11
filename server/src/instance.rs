use std::env;
use std::fs;
use std::str::FromStr;
use rayon::prelude::*;

use crate::{log_info};
use crate::types::JsonData;
use crate::rstatic::{INSTANCES, SESSION};

use crate::error::Error as Error;
use crate::error::Result as Result;
use crate::error::Error::Custom as Custom;
use crate::builder::Hexane as Hexane;
use crate::interface::wrap_message;

pub(crate) fn load_instance(args: Vec<String>) -> Result<()> {
    if args.len() != 3 {
        return Err(Custom("invalid arguments".to_string()))
    }

    log_info!(&"loading instance".to_string());

    let session = SESSION.lock()?;
    let mut instance = map_json_config(&args[2])?;

    instance.user_session.username = session.username.clone();
    instance.user_session.is_admin = session.is_admin.clone();
    instance.setup_build()?;

    wrap_message("info", &format!("{} is ready", instance.builder_cfg.output_name));
    INSTANCES.lock()?.push(instance);

    // TODO: insert db
    Ok(())
}

pub(crate) fn remove_instance(args: Vec<String>) -> Result<()> {
    if args.len() < 2 {
        return Err(Custom("invalid arguments".to_string()))
    }

    let mut instances = INSTANCES.lock()?;
    if let Some(select) = instances
        .iter()
        .position(
            |instance| instance.builder_cfg.output_name == args[2]) {

        wrap_message("info", &format!("removing {}", instances[select].builder_cfg.output_name));
        instances.remove(select);
        // TODO: remove from db

        Ok(())
    }
    else {
        Err(Custom("Implant not found".to_string()))
    }
}

pub(crate) fn interact_instance(args: Vec<String>) -> Result<()> {
    // todo: implement
    Ok(())
}

fn map_json_config(file_path: &String) -> Result<Hexane> {
    let json_file = env::current_dir()?
        .join("json")
        .join(file_path);

    let contents = fs::read_to_string(json_file)
        .map_err(Error::Io)?;

    let json_data = serde_json::from_str::<JsonData>(&contents)?;

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
