mod implants;
mod utils;
mod types;

use std::fs;
use clap::Parser;
use std::io::{self, Write};
use clap::builder::UnknownArgumentValueParser;
use serde::Deserialize;
use serde::ser::Impossible;
use serde_json::Result;
use crate::client::types::JsonData;

const BANNER: &str = r#"
██╗  ██╗███████╗██╗  ██╗ █████╗ ███╗   ██╗███████╗ ██████╗██████╗
██║  ██║██╔════╝╚██╗██╔╝██╔══██╗████╗  ██║██╔════╝██╔════╝╚════██╗
███████║█████╗   ╚███╔╝ ███████║██╔██╗ ██║█████╗  ██║      █████╔╝
██╔══██║██╔══╝   ██╔██╗ ██╔══██║██║╚██╗██║██╔══╝  ██║     ██╔═══╝
██║  ██║███████╗██╔╝ ██╗██║  ██║██║ ╚████║███████╗╚██████╗███████╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚══════╝"#;


struct Client {
    debug: bool,
    show_compiler: bool,
}
impl Client {
    fn read_json(file_path: &String) {

        let contents = fs::read_to_string(file_path).expect("invalid file path");
        let json: JsonData = serde_json::from_str(contents.as_str()).expect("invalid json syntax");

    }

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

            let args: Vec<String> = input.split_whitespace().collect();
            println!("{:?}", args);

            match args[0].as_str() {
                "load" => {
                    Self::read_json(&args[1]);
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
}
