use crossbeam_channel::{unbounded, Receiver, select};
use crossbeam_channel::Sender;
use crate::client::cursor;

#[derive(Debug)]
pub struct Message {
    pub(crate) msg_type: String,
    pub(crate) msg: String,
}

fn print_channel(receiver: Receiver<Message>, exit: Receiver<()>, debug: bool) {
    loop {
        select! {
            recv(exit) -> _ => {
                break;
            },
            recv(receiver) -> message => {
                if let Ok(m) = message {
                    if !debug && m.msg_type == "DBG" {
                        continue;
                    }
                    println!("[{}] {}", m.msg_type, m.msg);
                    cursor();
                }
            }
        }
    }
}

fn wrap_message(typ: &str, msg: &str, sender: &Sender<Message>) {
    let message = Message {
        msg_type: typ.to_string(),
        msg: msg.to_string(),
    };

    sender.send(message).unwrap();
}