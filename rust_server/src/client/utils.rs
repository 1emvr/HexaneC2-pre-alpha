use crossbeam_channel::{unbounded, Receiver, Sender, select};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::{env, io};

use clap::Parser;
use crate::client::types::{Args, Message};

use lazy_static::lazy_static;
lazy_static! {
    pub(crate) static ref CHANNEL: (Sender<Message>, Receiver<Message>) = unbounded();
    pub(crate) static ref EXIT: (Sender<()>, Receiver<()>)              = unbounded();

    pub(crate) static ref ARGS: Args            = Args::parse();
    pub(crate) static ref DEBUG: bool           = ARGS.debug;
    pub(crate) static ref SHOW_COMPILER: bool   = ARGS.show_compiler;
    pub(crate) static ref CURDIR: PathBuf       = env::current_dir().unwrap();
}

pub fn cursor() {
    print!(" > ");
    io::stdout().flush().unwrap();
}

pub fn print_channel() {
    let receiver    = &CHANNEL.1;
    let exit        = &EXIT.1;

    loop {
        select! {
            recv(exit) -> _ => {
                break;
            },
            recv(receiver) -> message => {
                if let Ok(m) = message {
                    if !*DEBUG && m.msg_type == "DBG" {
                        continue;
                    }
                    println!("[{}] {}", m.msg_type, m.msg);
                    cursor();
                }
            }
        }
    }
}

pub fn wrap_message(typ: &str, msg: String) {
    let sender = &CHANNEL.0;
    let message = Message {
        msg_type: typ.to_string(),
        msg: msg.to_string(),
    };

    sender.send(message).unwrap();
}

pub fn stop_print_channel() {
    let sender = &EXIT.0;
    sender.send(()).unwrap();
}