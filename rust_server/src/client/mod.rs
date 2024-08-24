use std::fmt::Debug;
use std::io::{Write};
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

    fn implants(args: Vec<&str>) {
        println!("{}", args);
    }

    fn help() {
        println!("help menu")
    }

    pub fn run_client() {
        Self::print_banner();

        let mut input = String::new();
        while input.as_str() != "exit" {
            println!(" > ");

            io::stdin().read_line(&mut input).expect("error reading user input");
            let args: Vec<&str> = input.split(" ").collect();

            match input.as_str() {
                "implant"   => Self::implants(args),
                "help"      => Self::help(),
                _ => println!("invalid input")
            }
        }
    }
}
