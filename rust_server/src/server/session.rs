use std::{env, thread};
use std::path::PathBuf;
use std::sync::Mutex;
use crossbeam_channel::{unbounded, Receiver, Sender};
use crate::server::types::{Message, UserSession};
use crate::server::utils::{print_channel, wrap_message};

use clap::Parser;
use lazy_static::lazy_static;
use crate::server::rstatic::SESSION;

const BANNER: &str = r#"
██╗  ██╗███████╗██╗  ██╗ █████╗ ███╗   ██╗███████╗ ██████╗██████╗
██║  ██║██╔════╝╚██╗██╔╝██╔══██╗████╗  ██║██╔════╝██╔════╝╚════██╗
███████║█████╗   ╚███╔╝ ███████║██╔██╗ ██║█████╗  ██║      █████╔╝
██╔══██║██╔══╝   ██╔██╗ ██╔══██║██║╚██╗██║██╔══╝  ██║     ██╔═══╝
██║  ██║███████╗██╔╝ ██╗██║  ██║██║ ╚████║███████╗╚██████╗███████╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚══════╝

"#;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// run with simple debug messages
    #[arg(short, long)]
    pub(crate) debug: bool,

    /// run with compiler output
    #[arg(short, long)]
    pub(crate) show_compiler: bool,
}


pub fn init() {
    thread::spawn(|| { print_channel(); });

    println!("{}", BANNER);
    get_session();
}

pub fn get_session() {
    let mut session = SESSION.lock().unwrap();

    session.username = "lemur".to_owned();
    session.is_admin = true;
}

