mod utils;
mod types;

use std::fs;
use clap::Parser;

use serde_json;
use serde_json::Error;
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

fn print_banner() {
    println!("{}", BANNER);
}

fn cursor() {
    print!(" > ");
    io::stdout().flush().unwrap();
}

fn init() {
    print_banner();

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
                let mut instance = map_json_config(&args[1]).expect("TODO: panic message");

                setup_instance(&mut instance);
                setup_server(&instance);

                instances.push(instance);
            },

            "exit" => break,
            _ => println!("invalid input")
        }
    }
}

fn setup_instance(instance: &mut Hexane) {

}

fn setup_server(instance: &Hexane) {

}

fn map_json_config(file_path: &String) -> Result<Hexane, Error> {

    let contents = fs::read_to_string("./json/".to_owned() + file_path.as_str()).expect("invalid file path");
    let json_data: JsonData = serde_json::from_str(contents.as_str()).expect("invalid json syntax");

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


