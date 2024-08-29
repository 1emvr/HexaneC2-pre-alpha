mod utils;
mod types;
mod error;
mod session;
mod config;
mod cipher;
mod stream;
mod instance;
mod listener;

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
use self::utils::{cursor, wrap_message, stop_print_channel};
use self::instance::load_instance;

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

        if args[0].as_str() == "exit" {
            break;
        } else {
            if args.len() < 2 {
                invalid_input!(args.join(" ").to_string());
                continue;
            }
        }

        match args[0].as_str() {

            "implant" => {
                match args[1].as_str() {
                    "load"  => { load_instance(args).unwrap_or_else(|e| wrap_message("error", e.to_string())) },
                    "ls"    => { todo!(); },
                    "rm"    => { todo!(); },
                    "i"     => { todo!(); }

                    _ => invalid_input!(args.join(" ").to_string())
                }
            },

            "listener" => {
                match args[1].as_str() {

                    // todo: "attach" - find implant by name and attach an associated listener
                    "attach" => { todo!() },

                    _ => invalid_input!(args.join(" ").to_string())
                }
            }

            _ => {
                wrap_message("error", format!("invalid input: {}", args[0]));
                continue;
            }
        }
    }

    stop_print_channel();
}
