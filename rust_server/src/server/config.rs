use std::env;
use std::path::PathBuf;
use std::sync::Mutex;
use crossbeam_channel::{unbounded, Receiver, Sender};
use crate::server::types::{Args, Message, UserSession};

use clap::Parser;
use lazy_static::lazy_static;

lazy_static! {
    pub(crate) static ref SESSION: Mutex<UserSession> = Mutex::new(UserSession{
        username: String::from(""),
        is_admin: false
    });

    pub(crate) static ref CHANNEL: (Sender<Message>, Receiver<Message>) = unbounded();
    pub(crate) static ref EXIT: (Sender<()>, Receiver<()>)              = unbounded();

    pub(crate) static ref ARGS: Args            = Args::parse();
    pub(crate) static ref DEBUG: bool           = ARGS.debug;
    pub(crate) static ref SHOW_COMPILER: bool   = ARGS.show_compiler;
    pub(crate) static ref CURDIR: PathBuf       = env::current_dir().unwrap();
}

fn get_session() {
    let mut session = SESSION.lock().unwrap();

    session.username = String::from("lemur");
    session.is_admin = true;
}

