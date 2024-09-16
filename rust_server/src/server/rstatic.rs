use std::env;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use clap::Parser;
use crossbeam_channel::{unbounded, Receiver as Recv, Sender as Send};
use lazy_static::lazy_static;
use crate::server::instance::Hexane;
use crate::server::session::Args;
use crate::server::types::{Message, UserSession};

lazy_static!(
    pub(crate) static ref ARGS: Args                                = Args::parse();
    pub(crate) static ref DEBUG: bool                               = ARGS.debug;
    pub(crate) static ref SHOW_COMPILER: bool                       = ARGS.show_compiler;
    pub(crate) static ref AMD64: String                             = String::from("amd64");

    pub(crate) static ref USERAGENT: String                         = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36".to_owned();
    pub(crate) static ref SESSION: Mutex<UserSession>               = Mutex::new(UserSession{ username: "".to_owned(), is_admin: false });
    pub(crate) static ref INSTANCES: Arc<Mutex<Vec<Hexane>>>        = Arc::new(Mutex::new(vec![]));

    pub(crate) static ref CHANNEL: (Send<Message>, Recv<Message>)   = unbounded();
    pub(crate) static ref EXIT: (Send<()>, Recv<()>)                = unbounded();
);

pub(crate) static STRINGS: &'static str         = "./configs/strings.txt";
pub(crate) static HASHES: &'static str          = "./core/include/names.hpp";
pub(crate) static DEBUG_FLAGS: &'static str     = "-std=c++23 -g -Os -nostdlib -fno-exceptions -fno-asynchronous-unwind-tables -masm=intel -fno-ident -fpack-struct=8 -falign-functions=1 -ffunction-sections -fdata-sections -falign-jumps=1 -w -falign-labels=1 -fPIC -fno-builtin '-Wl,--no-seh,--enable-stdcall-fixup,--gc-sections' ";
pub(crate) static RELEASE_FLAGS: &'static str   = "-std=c++23 -Os -nostdlib -fno-exceptions -fno-asynchronous-unwind-tables -masm=intel -fno-ident -fpack-struct=8 -falign-functions=1 -ffunction-sections -fdata-sections -falign-jumps=1 -w -falign-labels=1 -fPIC  -fno-builtin '-Wl,-s,--no-seh,--enable-stdcall-fixup,--gc-sections' ";

