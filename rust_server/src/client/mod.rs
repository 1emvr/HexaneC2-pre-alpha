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
use crate::client::types::{Hexane, HttpConfig, CompilerConfig, JsonData, UserSession};

const BANNER: &str = r#"
██╗  ██╗███████╗██╗  ██╗ █████╗ ███╗   ██╗███████╗ ██████╗██████╗
██║  ██║██╔════╝╚██╗██╔╝██╔══██╗████╗  ██║██╔════╝██╔════╝╚════██╗
███████║█████╗   ╚███╔╝ ███████║██╔██╗ ██║█████╗  ██║      █████╔╝
██╔══██║██╔══╝   ██╔██╗ ██╔══██║██║╚██╗██║██╔══╝  ██║     ██╔═══╝
██║  ██║███████╗██╔╝ ██╗██║  ██║██║ ╚████║███████╗╚██████╗███████╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚══════╝"#;

lazy_static! {
    static ref PAYLOADS: Mutex<Vec<LinkedList<Hexane>>> = Mutex::new(Vec::new());
    static ref SERVERS: Mutex<Vec<LinkedList<Hexane>>> = Mutex::new(Vec::new());
}


pub struct Client {
    pub(crate) debug: bool,
    pub(crate) show_compiler: bool,
}
impl Client {
    pub fn run_client() {
        println!("{}", BANNER);

        loop {
            let mut input = String::new();

            print!(" > ");
            io::stdout().flush().unwrap();
            io::stdin().read_line(&mut input).unwrap();

            let input = input.trim(); // remove any inner/outer whitespace
            if input.is_empty() {
                continue;
            }

            let args: Vec<String> = input.split_whitespace().map(str::to_string).collect();
            match args[0].as_str() {
                "load" => {
                    let instance = Config::map_json_config(&args[1]).expect("TODO: panic message");

                    LinkedList::<Hexane>::push_back(instance);
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

}

struct Config {
}

impl Config {
    fn map_json_config(file_path: &String) -> Result<Hexane, Error> {

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
        };

        Ok(instance)
    }
}

pub struct LinkedList<T> {
    pub(crate) head: Option<T>,
    pub(crate) next: Option<Box<LinkedList<T>>>,
}

impl<T> LinkedList<T> {
    pub fn new(instance: T) -> LinkedList<T> {
        LinkedList { head: Option::from(instance), next: None }
    }

    pub fn push_back(instance: T) {
        let new_payload = LinkedList::<Hexane>{ head: Option::from(instance), next: None };
        let mut payloads = PAYLOADS.lock().unwrap();

        payloads.push(new_payload);
    }
}

