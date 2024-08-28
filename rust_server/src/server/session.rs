use std::{env, thread};
use std::path::PathBuf;
use std::sync::Mutex;
use crossbeam_channel::{unbounded, Receiver, Sender};
use crate::server::types::{Args, Message, UserSession};

use clap::Parser;
use lazy_static::lazy_static;
use crate::server::BANNER;
use crate::server::utils::print_channel;

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

pub fn init() {
    println!("{}", BANNER);
    thread::spawn(|| { print_channel(); });

    if *DEBUG { println!("running in debug mode") }
    if *SHOW_COMPILER { println!("running with compiler output") }

    get_session();
}

pub fn get_session() {
    let mut session = SESSION.lock().unwrap();

    session.username = String::from("lemur");
    session.is_admin = true;
}

