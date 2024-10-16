use std::fs;
use std::env;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use prettytable::{row, Table};
use rayon::prelude::*;

use crate::error::Result;
use crate::error::Error::Custom;
use crate::interface::wrap_message;
use crate::types::{Hexane, JsonData, UserSession};

use crate::types::NetworkOptions::Http as HttpOpts;
use crate::types::NetworkOptions::Smb as SmbOpts;

use lazy_static::lazy_static;

lazy_static! {
    pub(crate) static ref INSTANCES: Arc<Mutex<Vec<Hexane>>> = Arc::new(Mutex::new(vec![]));
    pub(crate) static ref SESSION: Mutex<UserSession> = Mutex::new(UserSession {
        username: "".to_owned(),
        is_admin: false
    });
}

pub(crate) fn load_instance(args: Vec<String>) {
    if args.len() != 3 {
        wrap_message("error", "invalid arguments");
        return
    }

    wrap_message("INF", "loading json config");
    let mut instance = match map_json_config(&args[2]) {
        Ok(instance) => instance,
        Err(e) => {
            wrap_message("ERR", format!("loading instance failed: {e}").as_str());
            return
        }
    };

    let name = &instance.builder_cfg.output_name;

    wrap_message("INF", "setting up build");
    match instance.setup_build() {
        Ok(_) => wrap_message("INF", format!("{} is ready", name).as_str()),
        Err(e) => {
            wrap_message(&e.to_string(), "setup_build failed");
            return
        },
    }

    INSTANCES.lock().unwrap().push(instance);
}

pub(crate) fn remove_instance(args: Vec<String>) {
    if args.len() < 2 {
        wrap_message("error", "invalid arguments");
        return
    }

    let mut instances = INSTANCES
        .lock()
        .map_err(|_| {
            wrap_message("ERR", "instances could not be locked");
            return
        })
        .unwrap();

    let output_name = &args[2];
    if let Some(position) = instances.iter().position(|instance| instance.builder_cfg.output_name == *output_name) {
        wrap_message("INF", format!("removing {}", instances[position].builder_cfg.output_name).as_str());

        instances.remove(position);
        return
    }
    else {
        wrap_message("error", "implant not found");
        return
    }
}

fn map_json_config(file_path: &String) -> Result<Hexane> {
    let curdir = env::current_dir()
        .map_err(|e| {
            wrap_message("ERR", format!("could not get current directory: {e}").as_str());
            Err(e)
        })?;

    let mut json_file = curdir.join("json").join(file_path);

    if !json_file.exists() {
        wrap_message("error", "json file does not exist");
        return Err(Custom("fuck you".to_string()))
    }

    wrap_message("INF", "reading json content");
    let contents = fs::read_to_string(json_file)
        .map_err(|e| {
            wrap_message("ERR", format!("could not read json file: {e}").as_str());
            Err(e)
        });


    if &contents.is_empty() {
        wrap_message("error", "json doesn't seem to exist");
        return Err(Custom("fuck you".to_string()))
    }

    wrap_message("INF", "parsing json data");
    let json_data = serde_json::from_str::<JsonData>(&contents)
        .map_err(|e| {
            wrap_message("ERR", format!("could not parse json data: {e}").as_str());
            Err(e)
        });

    wrap_message("INF", "creating instance");
    let mut instance    = Hexane::default();
    let config          = json_data.unwrap();
    let session         = SESSION.lock();

    wrap_message("INF", "creating configuration");
    instance.group_id       = 0;
    instance.main_cfg       = config.config;
    instance.loader_cfg     = config.loader;
    instance.builder_cfg    = config.builder;
    instance.network_cfg    = config.network;
    instance.user_session   = session.unwrap().clone();

    Ok(instance)
}

pub fn list_instances() {
    let mut instances = INSTANCES
        .lock()
        .map_err(|_| {
            wrap_message("ERR", "instances could not be locked");
            return
        });

    match instances.unwrap() {
        Ok(instances) => {
            if instances.is_empty() {
                wrap_message("INF", "no active implants available");
                return
            }
        },
        Err(e) => {
            wrap_message("ERR", format!("fatal error, instances not mappable: {e}"));
            return
        }
    }

    let mut table = Table::new();
    table.set_titles(row!["gid", "pid", "name", "debug", "net_type", "address", "hostname", "domain", "proxy", "user", "active"]);

    for instance in &instances.unwrap().iter() {

        let gid = instance.group_id.to_string();
        let pid = instance.peer_id.to_string();
        let debug = instance.main_cfg.debug.to_string();
        let active = instance.active.to_string();

        let name = &instance.builder_cfg.output_name;
        let hostname = &instance.main_cfg.hostname;
        let username = &instance.user_session.username;

        let Some(network) = &instance.network_cfg else {
            wrap_message("error", "list_instances: the network type did not show up somehow");
            return
        };

        let (address, _net_type, domain, proxy) = match &network.options {
            HttpOpts(http) => {
                let net_type    = "http".to_string();
                let address     = format!("http://{}:{}", http.address, http.port);

                let domain = http.domain
                    .clone()
                    .unwrap_or_else(|| "null".to_string());

                let proxy = if let Some(proxy_config) = &http.proxy {
                    format!("{}://{}:{}", proxy_config.proto, proxy_config.address, proxy_config.port)
                }
                else {
                    "null".to_string()
                };

                (address, net_type, domain, proxy)
            }

            SmbOpts(smb) => {
                let address     = smb.egress_peer.clone();
                let net_type    = "smb".to_string();

                (address, net_type, "null".to_string(), "null".to_string())
            }
        };

        table.add_row(row![gid, pid, name, debug, address, hostname, domain, proxy, username, active, ]);
    }

    table.printstd();
}
