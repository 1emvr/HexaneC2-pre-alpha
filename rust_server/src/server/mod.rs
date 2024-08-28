mod utils;
mod types;
mod error;
mod session;

use std::fs;
use serde_json;
use serde::Deserialize;
use lazy_static::lazy_static;

use std::io::{self, Write};
use core::fmt::Display;
use std::sync::Mutex;

use self::error::{Error, Result};
use self::session::{init, CURDIR};
use self::types::{Hexane, JsonData, Compiler, UserSession};
use self::utils::{cursor, wrap_message, stop_print_channel};

lazy_static!(
    static ref instances: Mutex<Vec<Hexane>> = Mutex::new(vec![]);
);

pub fn run_client() {
    init();

    loop {
        cursor();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        let input = input.trim();
        if input.is_empty() {
            continue;
        }

        let args: Vec<String> = input.split_whitespace().map(str::to_string).collect();
        match args[0].as_str() {

            "load" => {
                load_instance(args);
            },

            "exit" => break,
            _ => {
                wrap_message("error", format!("invalid input: {}", args[0]));
                continue;
            }
        }
    }

    stop_print_channel();
}

fn load_instance(args: Vec<String>) {

    if args.len() < 2 {
        wrap_message("error", format!("invalid input: {} arguments", args.len()))
    }
    match map_json_config(&args[1]) {
        Ok(mut instance) => {
            setup_instance(&mut instance);
            setup_server(&instance);

            let build_dir   = instance.compiler.build_directory.as_str();
            let name        = instance.builder.output_name.as_str();
            let ext         = instance.compiler.file_extension.as_str();

            wrap_message("info", format!("{}/{}.{} is ready", build_dir, name, ext));
            instances.lock().unwrap().push(instance);
        }
        Err(err)=> {
            wrap_message("error", format!("map_json_config: {:?}", err))
        }
    }
}

fn setup_instance(instance: &mut Hexane) {

}

fn setup_server(instance: &Hexane) {

}

fn map_json_config(file_path: &String) -> Result<Hexane> {

    let json_file = CURDIR.join("json").join(file_path);
    let contents = fs::read_to_string(json_file).map_err(Error::Io)?;

    let json_data = match serde_json::from_str::<JsonData>(contents.as_str()) {
        Ok(data)    => data,
        Err(e)      => {
            wrap_message("debug", format!("{}", contents));
            return Err(Error::SerdeJson(e))
        }
    };

    let group_id = 0;
    let instance = Hexane {

        current_taskid: 0, peer_id: 0, group_id, build_type: 0, network_type: 0,
        crypt_key: vec![], shellcode: vec![], config_data: vec![],
        active: false,

        compiler: Compiler {
            file_extension:     String::from(""),
            build_directory:    String::from(""),
            compiler_flags:     vec![],
        },

        main:       json_data.config,
        network:    json_data.network,
        builder:    json_data.builder,
        loader:     json_data.loader,

        user_session: UserSession {
            username: String::from(""),
            is_admin: false,
        },
    };

    Ok(instance)
}


