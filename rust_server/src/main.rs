mod utils;

use std::io::{self, BufRead, Write};
use std::path::Path;
use std::sync::mpsc::{self, Receiver};
use std::{fs, thread};
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "HexaneC2", about = "Minimal command & control framework")]
struct Opt {
    #[structopt(short, long)]
    debug: bool,

    #[structopt(short = "c", long = "show-commands")]
    show_commands: bool,

    #[structopt(short = "j", long = "show-configs")]
    show_configs: bool,
}

fn main() {
    let opt = Opt::from_args();

    if opt.debug {
        wrap_message("INF", "running in debug mode");
    }
    if opt.show_commands {
        wrap_message("INF", "running with command output");
    }
    if opt.show_configs {
        wrap_message("INF", "running with json config output");
    }

    if let Err(e) = create_path("logs") {
        wrap_message("ERR", &format!("create logs path failed: {}", e));
        return;
    }
    if let Err(e) = create_path("build") {
        wrap_message("ERR", &format!("create build path failed: {}", e));
        return;
    }

    run_hexane(opt);
}

fn wrap_message(level: &str, message: &str) {
    println!("[{}] {}", level, message);
}

fn create_path(path: &str) -> io::Result<()> {
    if !Path::new(path).exists() {
        fs::create_dir_all(path)?;
    }
    Ok(())
}

fn run_hexane(opt: Opt) {
    let (sender, receiver) = mpsc::channel();
    let reader = io::stdin();

    println!("{}", banner());

    thread::spawn(move || {
        print_channel(receiver);
    });

    loop {
        let mut input = String::new();
        reader.lock().read_line(&mut input).unwrap();

        let args: Vec<&str> = input.trim().split_whitespace().collect();

        if args.is_empty() {
            continue;
        }

        if args[0] == "exit" {
            sender.send(true).unwrap();
            break;
        }

        if let Err(e) = execute_command(&args, &opt) {
            wrap_message("ERR", &e.to_string());
            continue;
        }
    }
}

fn execute_command(args: &[&str], opt: &Opt) -> Result<(), String> {
    // Here you would implement your commands logic based on the args and opt
    wrap_message("DBG", &format!("Executing command: {:?}", args));
    Ok(())
}

fn print_channel(receiver: Receiver<bool>) {
    loop {
        if let Ok(_) = receiver.recv() {
            break;
        }
    }
}

fn banner() -> &'static str { r#"
██╗  ██╗███████╗██╗  ██╗ █████╗ ███╗   ██╗███████╗     ██████╗██████╗
██║  ██║██╔════╝╚██╗██╔╝██╔══██╗████╗  ██║██╔════╝    ██╔════╝╚════██╗
███████║█████╗   ╚███╔╝ ███████║██╔██╗ ██║█████╗█████╗██║      █████╔╝
██╔══██║██╔══╝   ██╔██╗ ██╔══██║██║╚██╗██║██╔══╝╚════╝██║     ██╔═══╝
██║  ██║███████╗██╔╝ ██╗██║  ██║██║ ╚████║███████╗    ╚██████╗███████╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝     ╚═════╝╚══════╝"#
}
