mod error;
mod types;
mod utils;
mod config;
mod cipher;
mod stream;
mod session;
mod instance;
mod parser;
mod builder;
mod binary;

use serde_json;
use serde::Deserialize;
use lazy_static::lazy_static;

use rand::Rng;
use std::io::{self, Write};
use core::fmt::Display;
use std::str::FromStr;
use std::sync::Mutex;

use self::session::{init};
use self::utils::{cursor, wrap_message, stop_print_channel};
use self::instance::{Hexane, load_instance, interact_instance, list_instances, remove_instance};
use crate::{invalid_input, length_check};

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
            length_check!(args, 2);
        }

        match args[0].as_str() {
            "implant" => {

                length_check!(args, 2);
                match args[1].as_str() {
                    "load"  => { load_instance(args).unwrap_or_else(|e| wrap_message("error", e.to_string())) },
                    "ls"    => { list_instances(args).unwrap_or_else(|e| wrap_message("error", e.to_string())) },
                    "rm"    => { remove_instance(args).unwrap_or_else(|e| wrap_message("error", e.to_string())) },
                    "i"     => { interact_instance(args).unwrap_or_else(|e| wrap_message("error", e.to_string())) }

                    _ => invalid_input!(args.join(" ").to_string())
                }
            },

            "listener" => {
                length_check!(args, 2);
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
