mod error;
mod format;
mod utils;
mod types;
mod stream;
mod binary;
mod cipher;
mod rstatic;
mod instance;

use crate::instance::{interact_instance, load_instance, remove_instance};
use crate::utils::{print_channel, print_help, stop_print_channel};
use crate::format::list_instances;
use crate::rstatic::SESSION;

use serde_json;
use serde::Deserialize;

use rand::Rng;
use core::fmt::Display;
use std::str::FromStr;

use std::io::stdin;
use std::io::Write;
use std::thread;
use clap::Parser;

pub fn get_session() {
    let session = SESSION.lock().unwrap();
    session.username = "lemur".to_owned();
    session.is_admin = true;
}

pub fn init_print_channel() {
    thread::spawn(|| { print_channel(); });
    get_session();
}

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
                    log_error!(&"invalid input".to_string());
                    continue;
                }
                match args[1].as_str() {
                    "ls"    => list_instances().unwrap_or_else(|e| log_error!(&e.to_string())),
                    "load"  => load_instance(args).unwrap_or_else(|e| log_error!(&e.to_string())),
                    "rm"    => remove_instance(args).unwrap_or_else(|e| log_error!(&e.to_string())),
                    "i"     => interact_instance(args).unwrap_or_else(|e| log_error!(&e.to_string())),
                    _       => log_error!(&"invalid input".to_owned())

                }
            },

            "listener" => {
                /*
                todo: add listener
                connection to an "external listener"
                 */
                log_error!(&"listener not yet implemented".to_owned());
            }

            _ => { log_error!(&"invalid input".to_owned()) }
        }
    }

    stop_print_channel();
}