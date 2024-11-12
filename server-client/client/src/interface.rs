use std::thread;
use crossbeam_channel::select;
use crossbeam_channel::unbounded;
use crossbeam_channel::Receiver as Recv;
use crossbeam_channel::Sender as Send;

use hexlib::types::ChannelMessage;
use lazy_static::lazy_static;

lazy_static!(
    pub(crate) static ref CHANNEL: (Send<ChannelMessage>, Recv<ChannelMessage>) = unbounded();
    pub(crate) static ref EXIT: (Send<()>, Recv<()>) = unbounded();
);


pub fn print_channel() {
    let receiver = &CHANNEL.1;
    let exit = &EXIT.1;

    loop {
        select! {
            recv(exit) -> _ => {
                break;
            },
            recv(receiver) -> message => {
                if let Ok(m) = message {
                    println!("[{}] {}", m.msg_type, m.msg);
                }
            }
        }
    }
}

pub fn init_print_channel() {
    thread::spawn(|| print_channel());
}

pub fn stop_print_channel() {
    let sender = &EXIT.0;
    sender.send(()).unwrap();
}

pub fn wrap_message(typ: &str, msg: &str) {
    let sender = &CHANNEL.0;

    let message = ChannelMessage {
        msg_type:   typ.to_string(),
        msg:        msg.to_string(),
    };

    sender.send(message).unwrap();
}

