mod implants;

use clap::Parser;
use std::io;

const BANNER: &str = r#"
 _                                 ___ ____
| |__   _____  ____ _ _ __   ___  / __\___ \
| '_ \ / _ \ \/ / _` | '_ \ / _ \/ /    __) |
| | | |  __/>  < (_| | | | |  __/ /___ / __/
|_| |_|\___/_/\_\__,_|_| |_|\___\____/|_____|
"#;


pub struct Client {
    // todo: implement with crossterm
}

impl Client {
    fn print_banner() {
        println!("{}", BANNER);
    }

    pub fn run_client() {
        Self::print_banner();

        let mut input = String::new().split_whitespace();
        let select = input.next().unwrap_or_default();
        let collect: Vec<&str> = select.collect();

        if select == "implant" {
            if let Some((command, args)) = collect.split_first() {
                match *command {
                    _ => println!("invalid arguments")
                }
            }
        } else {
            println!("invalid arguments");
        }
    }
}
