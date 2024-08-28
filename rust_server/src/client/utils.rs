use crossbeam_channel::{select};
use colored::*;

use std::io;
use std::io::Write;

use crate::client::config::{SESSION, CHANNEL, DEBUG, EXIT};
use crate::client::types::{Args, Message};

pub fn cursor() {
    print!(format!("{} >", *SESSION.username));
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
                    if !*DEBUG && m.msg_type == "dbg" {
                        continue;
                    }
                    let fmt_msg = match m.msg_type.as_str() {
                        "err" => format!("{}", m.msg_type.red()),
                        _       => m.msg_type,
                    };
                    println!("[{}] {}", fmt_msg, m.msg);
                    cursor();
                }
            }
        }
    }
}

pub fn wrap_message(typ: &str, msg: String) {
    let sender = &CHANNEL.0;
    let message = Message { msg_type: typ.to_string(), msg: msg.to_string(),};

    sender.send(message).unwrap();
}

pub fn stop_print_channel() {
    let sender = &EXIT.0;
    sender.send(()).unwrap();
}