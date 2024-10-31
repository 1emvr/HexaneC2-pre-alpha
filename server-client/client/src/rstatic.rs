use crate::types::Message;

use crossbeam_channel::unbounded;
use crossbeam_channel::Receiver as Recv;
use crossbeam_channel::Sender as Send;

use clap::Parser;
use lazy_static::lazy_static;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(short, long)]
    pub(crate) debug: bool,

    #[arg(short, long)]
    pub(crate) show_compiler: bool,
}

lazy_static!(
    pub(crate) static ref ARGS: Args                                = Args::parse();
    pub(crate) static ref DEBUG: bool                               = ARGS.debug;
    pub(crate) static ref SHOW_COMPILER: bool                       = ARGS.show_compiler;
    pub(crate) static ref AMD64: String                             = String::from("amd64");

    pub(crate) static ref USERAGENT: String                         = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36".to_owned();
    pub(crate) static ref CHANNEL: (Send<Message>, Recv<Message>)   = unbounded();
    pub(crate) static ref EXIT: (Send<()>, Recv<()>)                = unbounded();
);


