mod error;
mod types;
mod utils;
mod cipher;
mod stream;
mod parser;
mod session;
mod binary;
mod format;
mod instance;
mod rstatic;

use serde_json;
use serde::Deserialize;

use std::str::FromStr;
use std::io::{stdin, Write};
use core::fmt::Display;
use rand::Rng;

use self::session::init;
use self::format::list_instances;
use self::utils::{wrap_message, stop_print_channel, print_help};
use self::instance::{load_instance, interact_instance, remove_instance};


pub fn run_client() {
    init();

    loop {
        let mut input = String::new();
        stdin().read_line(&mut input).unwrap();

        let input = input.trim();
        if input.is_empty() {
            continue;
        }

        let args: Vec<String> = input.split_whitespace().map(str::to_string).collect();

        match args[0].as_str() {
            "exit"      => break,
            "help"      => print_help(),
            "implant"   => {

                if args.len() < 2 {
                    wrap_message("error", &"invalid input".to_owned());
                    continue;
                }
                match args[1].as_str() {
                    "ls"    => list_instances().unwrap_or_else(|e| wrap_message("error", &e.to_string())),
                    "load"  => load_instance(args).unwrap_or_else(|e| wrap_message("error", &e.to_string())),
                    "rm"    => remove_instance(args).unwrap_or_else(|e| wrap_message("error", &e.to_string())),
                    "i"     => interact_instance(args).unwrap_or_else(|e| wrap_message("error", &e.to_string())),
                    _       => wrap_message("error", &"invalid input".to_owned())

                }
            },

            "listener" => {
                // todo: add listener
                wrap_message("error", &"listener not yet implemented".to_owned());
            }

            _ => {
                wrap_message("error", &"invalid input".to_owned())
            }
        }
    }

    stop_print_channel();
}

