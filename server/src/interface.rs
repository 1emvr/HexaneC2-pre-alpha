use std::thread;
use crossbeam_channel::select;

use crate::rstatic::{CHANNEL, DEBUG, EXIT, SESSION};
use crate::types::Message;

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
                    if !*DEBUG && m.msg_type == "debug" { continue; }

                    println!("[{}] {}", m.msg_type, m.msg);
                }
            }
        }
    }
}

pub fn stop_print_channel() {
    let sender = &EXIT.0;
    sender.send(()).unwrap();
}

pub fn init_print_channel() {
    thread::spawn(|| { print_channel(); });
    get_session();
}

pub fn get_session() {
    let mut session = SESSION.lock().unwrap();
    session.username = "lemur".to_owned();
    session.is_admin = true;
}

pub fn wrap_message(typ: &str, msg: &str) {
    let sender = &CHANNEL.0;

    let message = Message {
        msg_type:   typ.to_string(),
        msg:        msg.to_string(),
    };

    sender.send(message).unwrap();
}

