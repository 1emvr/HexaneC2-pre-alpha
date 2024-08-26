mod utils;
mod types;
mod implants;

use std::fs;
use clap::Parser;
use serde::Deserialize;
use serde_json;

use std::io::{self, Write};
use std::sync::Mutex;
use lazy_static::lazy_static;
use serde_json::Error;
use crate::client::types::{Hexane, CompilerConfig, JsonData, UserSession, SavedPayloads, SavedServers};

const BANNER: &str = r#"
██╗  ██╗███████╗██╗  ██╗ █████╗ ███╗   ██╗███████╗ ██████╗██████╗
██║  ██║██╔════╝╚██╗██╔╝██╔══██╗████╗  ██║██╔════╝██╔════╝╚════██╗
███████║█████╗   ╚███╔╝ ███████║██╔██╗ ██║█████╗  ██║      █████╔╝
██╔══██║██╔══╝   ██╔██╗ ██╔══██║██║╚██╗██║██╔══╝  ██║     ██╔═══╝
██║  ██║███████╗██╔╝ ██╗██║  ██║██║ ╚████║███████╗╚██████╗███████╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚══════╝"#;

lazy_static! {
    static ref SAVED_PAYLOADS: Mutex<Vec<SavedPayloads>> = Mutex::new(Vec::new());
}

struct Client {
    debug: bool,
    show_compiler: bool,
}
impl Client {
    pub fn run_client() {
        println!("{}", BANNER);

        Self::debug = true;

        loop {
            let mut input = String::new();

            print!(" > ");
            io::stdout().flush().unwrap();
            io::stdin().read_line(&mut input).unwrap();

            let input = input.trim(); // remove any inner/outer whitespace
            if input.is_empty() {
                continue;
            }

            let args: Vec<String> = input.split_whitespace().collect();
            println!("{:?}", args);

            match args[0].as_str() {
                "load" => {
                    Self::map_json_config(&args[1]).expect("TODO: panic message");
                    todo!()
                },
                "ls" => {
                    todo!()
                },
                "rm" => {
                    todo!()
                },
                "i" => {
                    todo!()
                },
                _ => println!("invalid input")
            }

        }
    }

    fn map_json_config(file_path: &String) -> Result<(), Error> {

        let group_id: i32 = 0;
        let contents = fs::read_to_string(file_path).expect("invalid file path");
        let json_data: JsonData = serde_json::from_str(contents.as_str()).expect("invalid json syntax");

        let instance = Hexane {
            current_taskid: 0,
            peer_id:        0,
            group_id,
            build_type:     0,
            crypt_key:      vec![],
            shellcode:      vec![],
            config_data:    vec![],
            network_type:   0,
            active:         false,
            main:           json_data.config,

            compiler: CompilerConfig {
                file_extension:     String::from(""),
                build_directory:    String::from(""),
                compiler_flags:     vec![],
            },
            network:    json_data.network,
            builder:    json_data.builder,
            loader:     json_data.loader,

            user_session: UserSession {
                username: String::from(""),
                is_admin: false,
            },
            next: None,
        };

        Self::save_payload(instance, 1);
        if Self::debug {
            println!("saved: {}", &instance.builder.output_name);
        }

        Ok(())
    }

    fn save_payload(instance: Hexane, group_id: i8) {
        let new_payload = SavedPayloads {
            head: instance,
            group: group_id,
        };

        let mut payloads = SAVED_PAYLOADS.lock().unwrap();
        payloads.push(new_payload);
    }
}
