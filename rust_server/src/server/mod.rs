mod utils;
mod types;
mod error;
mod session;

use serde_json;
use serde::Deserialize;

use std::io::{self, Write};
use self::error::{Error, Result};
use self::types::{Hexane, JsonData, Compiler, UserSession};
use self::utils::{cursor, wrap_message, stop_print_channel};
use self::session::{init, CURDIR};

const BANNER: &str = r#"
██╗  ██╗███████╗██╗  ██╗ █████╗ ███╗   ██╗███████╗ ██████╗██████╗
██║  ██║██╔════╝╚██╗██╔╝██╔══██╗████╗  ██║██╔════╝██╔════╝╚════██╗
███████║█████╗   ╚███╔╝ ███████║██╔██╗ ██║█████╗  ██║      █████╔╝
██╔══██║██╔══╝   ██╔██╗ ██╔══██║██║╚██╗██║██╔══╝  ██║     ██╔═══╝
██║  ██║███████╗██╔╝ ██╗██║  ██║██║ ╚████║███████╗╚██████╗███████╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚══════╝"#;


pub fn run_client() {
    init();

    let mut instances: Vec<Hexane> = Vec::new();
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
                if args.len() < 2 {
                    wrap_message("err", format!("invalid input: {} arguments", args.len()));
                    continue;
                }
                match map_json_config(&args[1]) {
                    Ok(mut instance) => {
                        setup_instance(&mut instance);
                        setup_server(&instance);

                        instances.push(instance);
                    }
                    Err(err)=> {
                        wrap_message("err", format!("map_json_config: {}", err));
                        continue;
                    }
                }
            },

            "exit" => break,
            _ => {
                wrap_message("err", format!("invalid input: {}", args[0]));
                continue;
            }
        }
    }

    stop_print_channel();
}

fn map_json_config(file_path: &String) -> Result<Hexane> {
    let json_file = CURDIR.join("json").join(file_path);

    let contents: String = fs::read_to_string(json_file).map_err(Error::Io)?;
    let json_data: Result<JsonData> = serde_json::from_str(contents.as_str()).map_err(Error::SerdeJson)?;

    let group_id = 0;
    let data = json_data?;

    let instance = Hexane {

        current_taskid: 0, peer_id: 0, group_id, build_type: 0, network_type: 0,
        crypt_key: vec![], shellcode: vec![], config_data: vec![],
        active: false,

        compiler: Compiler {
            file_extension:     String::from(""),
            build_directory:    String::from(""),
            compiler_flags:     vec![],
        },

        main:       data.config,
        network:    data.network,
        builder:    data.builder,
        loader:     data.loader,

        user_session: UserSession {
            username: String::from(""),
            is_admin: false,
        },
    };

    Ok(instance)
}

fn setup_instance(instance: &mut Hexane) {

}

fn setup_server(instance: &Hexane) {

}

