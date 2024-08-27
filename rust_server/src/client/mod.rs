mod utils;
mod types;

use std::fs;
use clap::Parser;
use serde::Deserialize;
use serde_json;

use core::ptr::NonNull;
use std::io::{self, Write};
use lazy_static::lazy_static;
use serde_json::Error;
use crate::client::types::{Hexane, JsonData, CompilerConfig, UserSession};

const BANNER: &str = r#"
██╗  ██╗███████╗██╗  ██╗ █████╗ ███╗   ██╗███████╗ ██████╗██████╗
██║  ██║██╔════╝╚██╗██╔╝██╔══██╗████╗  ██║██╔════╝██╔════╝╚════██╗
███████║█████╗   ╚███╔╝ ███████║██╔██╗ ██║█████╗  ██║      █████╔╝
██╔══██║██╔══╝   ██╔██╗ ██╔══██║██║╚██╗██║██╔══╝  ██║     ██╔═══╝
██║  ██║███████╗██╔╝ ██╗██║  ██║██║ ╚████║███████╗╚██████╗███████╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚══════╝"#;

lazy_static! {
    static ref PAYLOADS: LinkedList<Hexane> = LinkedList::<Hexane>::new();
}


pub struct Client {
    pub(crate) debug: bool,
    pub(crate) show_compiler: bool,
}
impl Client {
    fn print_banner() {
        println!("{}", BANNER);
    }

    pub fn run_client() {
        Self::print_banner();

        let mut payloads: LinkedList<Hexane> = LinkedList::<Hexane>::new();
        loop {
            print!(" > ");

            let mut input = String::new();

            io::stdout().flush().unwrap();
            io::stdin().read_line(&mut input).unwrap();

            let input = input.trim();
            if input.is_empty() {
                continue;
            }

            let args: Vec<String> = input.split_whitespace().map(str::to_string).collect();
            match args[0].as_str() {
                "load" => {
                    let instance = map_json_config(&args[1]).expect("TODO: panic message");

                    payloads.push(instance);
                },
                "rm" => {
                    todo!()
                },
                "ls" => {
                    todo!()
                },
                "i" => {
                    todo!()
                },
                _ => println!("invalid input")
            }

        }
    }
}

pub struct LinkedList<T> {
    pub(crate) head: Option<T>,
    pub(crate) next: Option<NonNull<LinkedList<T>>>,
}

impl LinkedList<Hexane> {
    pub fn new() -> LinkedList<Hexane> {
        LinkedList {
            head: None,
            next: None,
        }
    }

    pub fn push(mut self, instance: Hexane) {
        let new_head = Box::new(LinkedList::<Hexane> {
            head: Some(instance),
            next: None,
        });

        if self.next.is_none() {
            let pointer: NonNull<LinkedList<Hexane>> = Box::leak(new_head).into();
            self.next = Some(pointer);

        } else {
            let mut pointer: NonNull<LinkedList<Hexane>> = Box::leak(new_head).into();
            unsafe {
                pointer.as_mut().next = self.next;
            }
            self.next = Some(pointer);
        }
    }

    pub fn pop(&mut self) -> Option<Hexane> {
        if self.next.is_none() {
            None

        } else {
            let mut next = self.next.unwrap();
            let only_one: bool = unsafe { next.as_mut().next.is_none() };

            if only_one == true {
                let next_box = unsafe { Box::from_raw(next.as_ptr()) };

                self.next = None;
                next_box.head
            } else {
                let next_next = unsafe { next.as_mut().next };
                let next_box = unsafe { Box::from_raw(next.as_ptr()) };

                self.next = next_next;
                next_box.head
            }
        }
    }
}

fn map_json_config(file_path: &String) -> Result<Hexane, Error> {

    let contents = fs::read_to_string(file_path).expect("invalid file path");
    let json_data: JsonData = serde_json::from_str(contents.as_str()).expect("invalid json syntax");

    let instance = Hexane {
        current_taskid: 0,
        peer_id:        0,
        group_id,
        build_type:     0,
        crypt_key:      vec![],
        shellcode:      vec![],
        config_data:    vec![],
        network_type:   0,
        active:         false,
        main:           json_data.config,

        compiler: CompilerConfig {
            file_extension:     String::from(""),
            build_directory:    String::from(""),
            compiler_flags:     vec![],
        },
        network:    json_data.network,
        builder:    json_data.builder,
        loader:     json_data.loader,

        user_session: UserSession {
            username: String::from(""),
            is_admin: false,
        },
        next: None,
    };

    Ok(instance)
}


