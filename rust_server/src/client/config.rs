use std::env;
use std::path::PathBuf;

use crossbeam_channel::{unbounded, Receiver, Sender};
use crate::client::types::{Args, Message, UserSession};

use clap::Parser;
use lazy_static::lazy_static;

lazy_static! {
    pub(crate) static ref SESSION: UserSession = UserSession{
        .username = "lemur",
        .is_admin = true
    };

    pub(crate) static ref CHANNEL: (Sender<Message>, Receiver<Message>) = unbounded();
    pub(crate) static ref EXIT: (Sender<()>, Receiver<()>)              = unbounded();

    pub(crate) static ref ARGS: Args            = Args::parse();
    pub(crate) static ref DEBUG: bool           = ARGS.debug;
    pub(crate) static ref SHOW_COMPILER: bool   = ARGS.show_compiler;
    pub(crate) static ref CURDIR: PathBuf       = env::current_dir().unwrap();
}

