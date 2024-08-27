mod utils;
mod types;

use std::fs;
use clap::Parser;

use serde_json;
use serde_json::{Result, Error};
use serde::Deserialize;

use std::io::{self, Write};
use lazy_static::lazy_static;
use crate::client::types::{Hexane, JsonData, CompilerConfig, UserSession, Args};

const BANNER: &str = r#"
██╗  ██╗███████╗██╗  ██╗ █████╗ ███╗   ██╗███████╗ ██████╗██████╗
██║  ██║██╔════╝╚██╗██╔╝██╔══██╗████╗  ██║██╔════╝██╔════╝╚════██╗
███████║█████╗   ╚███╔╝ ███████║██╔██╗ ██║█████╗  ██║      █████╔╝
██╔══██║██╔══╝   ██╔██╗ ██╔══██║██║╚██╗██║██╔══╝  ██║     ██╔═══╝
██║  ██║███████╗██╔╝ ██╗██║  ██║██║ ╚████║███████╗╚██████╗███████╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚══════╝"#;

lazy_static! {
    pub(crate) static ref ARGS: Args           = Args::parse();
    pub(crate) static ref DEBUG: bool          = ARGS.debug;
    pub(crate) static ref SHOW_COMPILER: bool  = ARGS.show_compiler;
}

fn cursor() {
    print!(" > ");
    io::stdout().flush().unwrap();
}

fn init() {
    println!("{}", BANNER);

    if *DEBUG { println!("running in debug mode") }
    if *SHOW_COMPILER { println!("running with compiler output") }
}

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
                match map_json_config(&args[1]) {
                    Ok(mut instance) => {
                        setup_instance(&mut instance);
                        setup_server(&instance);

                        instances.push(instance);
                    }
                    Err(err)=> {
                        println!("failed to load json config: {err}");
                        continue;
                    }
                }
            },

            "exit" => break,
            _ => println!("invalid input")
        }
    }
}

#[derive(Error, Debug)]
pub enum JsonError {
    #[error("error reading file")]
    InvalidFile(String),

    #[error("error parsing json")]
    InvalidJson(String),
}

fn map_json_config(file_path: &String) -> Result<Hexane> {

    let json_file = "./json/".to_owned() + file_path.as_str();
    let contents = match fs::read_to_string(&json_file) {
        Ok(contents) => contents,
        Err(err) => {
            eprintln!("error reading {json_file}: {err}");
            return err;
        }
    };

    let json_data: JsonData = match serde_json::from_str(contents.as_str()) {
        Ok(json_data) => json_data,
        Err(err) => {
            eprintln!("error parsing json data: {err}");
            return err;
        }
    };

    let group_id = 0;
    let instance = Hexane {

        current_taskid: 0, peer_id: 0, group_id, build_type: 0, network_type: 0,
        crypt_key: vec![], shellcode: vec![], config_data: vec![],
        active: false,

        compiler: CompilerConfig {
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

fn setup_instance(instance: &mut Hexane) {

}

fn setup_server(instance: &Hexane) {

}

