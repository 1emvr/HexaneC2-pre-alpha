mod ws;
mod utils;
mod cipher;
mod binary;
mod instance;
mod rstatic;
mod builder;
mod interface;

use clap::Parser;
use std::str::FromStr;
use std::io::stdin;

use crate::instance::{list_instances, load_instance, remove_instance};
use crate::interface::{init_print_channel, stop_print_channel, wrap_message};
use crate::utils::print_help;
use crate::ws::ws_session;


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
                    wrap_message("ERR", "invalid input");
                    continue;
                }

                match args[1].as_str() {
                    "ls"    => list_instances(),
                    "load"  => load_instance(args),
                    "rm"    => remove_instance(args),
                    _       => wrap_message("ERR", "invalid input")
                }
            },

            "listener" => {

				if args.len() != 3 {
					wrap_message("ERR", "invalid input"),
					continue;
				}

				match args[1].as_str() {
                    "connect" => ws_session(args[2]); // NOTE: returned results aren't necessary in the main loop. All errors are handled by callee.
                    _         => wrap_message("ERR", "invalid input"),
                }
            }
            _ => {
                wrap_message("ERR", "invalid input")
            }
        }
    }

    stop_print_channel();
}
