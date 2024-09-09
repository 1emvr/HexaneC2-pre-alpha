mod error;
mod types;
mod utils;
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
use std::io::{stdin, Write};
use core::fmt::Display;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use self::session::{init};
use self::utils::{wrap_message, stop_print_channel};
use self::instance::{Hexane, load_instance, interact_instance, remove_instance};
use crate::server::format::list_instances;
use crate::{invalid_input, length_check_continue};

lazy_static!(
    pub(crate) static ref INSTANCES: Arc<Mutex<Vec<Hexane>>> = Arc::new(Mutex::new(vec![]));
);

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
                // todo: add listener
                wrap_message("error", format!("listener not yet implemented"));
            }

            _ => {
                invalid_input!(args.join(" ").to_string());
            }
        }
    }

    stop_print_channel();
}

pub fn print_help() {
    println!(r#"
Available Commands:

General:
  exit        - Exit the application
  help        - Display this help message

Implant Management:
  implant ls       - List all loaded implants
  implant load     - Load an implant from a specified configuration
  implant rm       - Remove a loaded implant
  implant i        - Interact with a specific loaded implant

Listener Management:
  listener attach  - Attach to a listener associated with an implant (not implemented)

"#);
}
