use std::{env, thread};
use std::path::PathBuf;
use std::sync::Mutex;
use crossbeam_channel::{unbounded, Receiver, Sender};
use crate::server::types::{Message, UserSession};
use crate::server::utils::{print_channel, wrap_message};

use clap::Parser;
use lazy_static::lazy_static;

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

lazy_static! {
    pub(crate) static ref SESSION: Mutex<UserSession> = Mutex::new(UserSession{
        username: String::from(""),
        is_admin: false
    });

    pub(crate) static ref CHANNEL: (Sender<Message>, Receiver<Message>) = unbounded();
    pub(crate) static ref EXIT: (Sender<()>, Receiver<()>)              = unbounded();

    pub(crate) static ref ARGS: Args            = Args::parse();
    pub(crate) static ref CURDIR: PathBuf       = env::current_dir().unwrap();
    pub(crate) static ref DEBUG: bool           = ARGS.debug;
    pub(crate) static ref SHOW_COMPILER: bool   = ARGS.show_compiler;

    pub(crate) static ref USERAGENT: String = String::from("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36");
}


pub fn init() {
    thread::spawn(|| { print_channel(); });
    println!("{}", BANNER);

    if *DEBUG { wrap_message("info", "running in debug mode".to_string()) }
    if *SHOW_COMPILER { wrap_message("info", "running with compiler output".to_string()) }

    get_session();
}

pub fn get_session() {
    let mut session = SESSION.lock().unwrap();

    session.username = String::from("lemur");
    session.is_admin = true;
}

