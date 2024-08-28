mod utils;
mod types;
mod error;

use std::{env, fs};
use clap::Parser;

use serde_json;
use serde::Deserialize;

use std::io::{self, Write};
use std::path::PathBuf;

use self::error::{Error, Result};
use self::types::{Args, Hexane, JsonData, Compiler, UserSession};

const BANNER: &str = r#"
██╗  ██╗███████╗██╗  ██╗ █████╗ ███╗   ██╗███████╗ ██████╗██████╗
██║  ██║██╔════╝╚██╗██╔╝██╔══██╗████╗  ██║██╔════╝██╔════╝╚════██╗
███████║█████╗   ╚███╔╝ ███████║██╔██╗ ██║█████╗  ██║      █████╔╝
██╔══██║██╔══╝   ██╔██╗ ██╔══██║██║╚██╗██║██╔══╝  ██║     ██╔═══╝
██║  ██║███████╗██╔╝ ██╗██║  ██║██║ ╚████║███████╗╚██████╗███████╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚══════╝"#;

use lazy_static::lazy_static;
lazy_static! {
    pub(crate) static ref ARGS: Args            = Args::parse();
    pub(crate) static ref DEBUG: bool           = ARGS.debug;
    pub(crate) static ref SHOW_COMPILER: bool   = ARGS.show_compiler;
    pub(crate) static ref CURDIR: PathBuf       = env::current_dir().unwrap();
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

