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
use crate::ws::ws_interactive;

