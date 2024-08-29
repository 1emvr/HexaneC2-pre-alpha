mod utils;
mod types;
mod error;
mod session;
mod config;
mod cipher;
mod stream;

use serde_json;
use serde::Deserialize;
use lazy_static::lazy_static;

use rand::Rng;
use std::io::{self, Write};
use core::fmt::Display;
use std::str::FromStr;
use std::sync::Mutex;
use crate::invalid_input;
use self::types::{Hexane};
use self::session::{init};
use self::config::{load_instance};
use self::utils::{cursor, wrap_message, stop_print_channel};

lazy_static!(
    static ref INSTANCES: Mutex<Vec<Hexane>> = Mutex::new(vec![]);
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

            "implant" => {
                if args.len() < 2 {
                    invalid_input!(args.join(" ").to_string());
                    continue;
                }

                match args[1].as_str() {
                    "load"  => { load_instance(args).unwrap_or_else(|e| wrap_message("error", e.to_string())) },
                    "ls"    => { todo!(); },
                    "rm"    => { todo!(); },
                    "i"     => { todo!(); }

                    _ => invalid_input!(args.join(" ").to_string())
                }
            },

            "listener" => {
                if args.len() < 2 {
                    invalid_input!(args.join(" ").to_string());
                    continue;
                }

                match args[1].as_str() {
                    // todo: attach - find implant by name and attach an associated listener
                    "attach" => { },

                    _ => invalid_input!(args.join(" ").to_string())
                }
            }

            "exit" => break,
            _ => {
                wrap_message("error", format!("invalid input: {}", args[0]));
                continue;
            }
        }
    }

    stop_print_channel();
}
