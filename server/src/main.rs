mod error;
mod utils;
mod types;
mod stream;
mod binary;
mod cipher;
mod rstatic;
mod instance;
mod builder;
mod interface;
mod parser;

use crate::instance::{list_instances, load_instance, remove_instance};
use crate::interface::{init_print_channel, stop_print_channel, wrap_message};
use crate::utils::print_help;

use serde_json;
use serde::Deserialize;

use rand::Rng;
use core::fmt::Display;
use std::str::FromStr;

use std::io::stdin;
use std::io::Write;
use clap::Parser;


fn main() {
    init_print_channel();

    loop {
        let mut user_input = String::new();

        stdin().read_line(&mut user_input)
            .unwrap();

        let user_input = user_input.trim();
        if user_input.is_empty() {
            continue;
        }

        let args: Vec<String> = user_input
            .split_whitespace()
            .map(str::to_string)
            .collect();

        match args[0].as_str() {
            "exit"      => break,
            "help"      => print_help(),

            "implant"   => {
                if args.len() < 2 {
                    wrap_message("error", "invalid input");
                    continue;
                }

                match args[1].as_str() {
                    "ls"    => list_instances(),
                    "load"  => load_instance(args),
                    "rm"    => remove_instance(args),
                    _       => wrap_message("error", "invalid input")
                }
            },

            "listener" => {
                // TODO: add connection to an external listener
                match args[1].as_str() {
                    "connect"   => wrap_message("error", "listener not yet implemented"),
                    _           => wrap_message("error", "listener not yet implemented"),
                }
            }
            _ => {
                wrap_message("error", "invalid input")
            }
        }
    }

    stop_print_channel();
}