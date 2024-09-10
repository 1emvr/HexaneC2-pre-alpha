use std::fs::{File, ReadDir};
use crossbeam_channel::{select};
use colored::*;

use std::{fs, io};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::io::{ErrorKind, BufRead, BufReader, Write};

use crate::return_error;
use crate::server::error::{Result, Error, Error::Io};
use crate::server::rstatic::{CHANNEL, DEBUG, EXIT};
use crate::server::types::{Message};
use crate::server::stream::Stream;


pub fn print_help() {
    println!(r#"
Available Commands:

General:
  exit        - Exit the application
  help        - Display this help message

Implant Management:
  implant ls       - List all loaded implants
  implant load     - Load an implant from a specified configuration
  implant rm       - Remove a loaded implant
  implant i        - Interact with a specific loaded implant

Listener Management:
  listener attach  - Attach to a listener associated with an implant (not implemented)

"#);
}


fn encode_utf16(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect()
}

pub fn print_channel() {
    let receiver    = &CHANNEL.1;
    let exit        = &EXIT.1;

    loop {
        select! {
            recv(exit) -> _ => {
                break;
            },
            recv(receiver) -> message => {
                if let Ok(m) = message {
                    if !*DEBUG && m.msg_type == "debug" {
                        continue;
                    }
                    let fmt_msg = match m.msg_type.as_str() {
                        "error" => format!("{}", m.msg_type),
                        _       => m.msg_type,
                    };
                    println!("[{}] {}", fmt_msg, m.msg);
                }
            }
        }
    }
}

pub fn wrap_message(typ: &str, msg: &String) {
    let sender = &CHANNEL.0;
    let message = Message { msg_type: typ.to_string(), msg: msg.to_string(),};

    sender.send(message).unwrap();
}

pub fn stop_print_channel() {
    let sender = &EXIT.0;
    sender.send(()).unwrap();
}

pub(crate) fn get_embedded_strings(str_list: Vec<String>) -> Vec<u8> {
    let mut stream = Stream::new();
    for s in str_list {
        stream.pack_string(&s);
    }

    stream.buffer
}

pub(crate) fn create_cpp_array(buffer: &[u8], length: usize) -> Vec<u8> {
    let mut array = "{".to_owned();

    for (i, &byte) in buffer.iter().enumerate() {
        if i == length - 1 {
            array += &format!("0x{:02X}", byte);
        }
        else {
            array += &format!("0x{:02X},", byte);
        }
    }

    array += "}";
    array.into_bytes()
}

pub(crate) fn create_hash_macro(s: &str) -> String {
    let macro_name  = s.to_uppercase().trim_end().to_string();
    let lower       = s.to_lowercase();

    let (name, is_unicode) = if lower.ends_with(".dll") {
        (encode_utf16(&lower), true)
    }
    else {
        (lower.into_bytes(), false)
    };

    format!(
        "#define {} 0x{:x}",
        macro_name.split('.').next().unwrap(),
        crate::server::cipher::get_hash_from_string(&String::from_utf8_lossy(&name), is_unicode)
    )
}

pub(crate) fn generate_hashes(strings_file: &str, out_file: &str) -> Result<()> {
    let str_file    = File::open(strings_file)?;
    let scanner     = BufReader::new(str_file).lines();

    let hashes: Vec<String> = scanner.filter_map(|line| line.ok())
        .map(|line| create_hash_macro(&line))
        .collect();

    let text = hashes.join("\n");
    fs::write(out_file, text)?;

    Ok(())
}

pub(crate) fn find_double_u32(data: &[u8], egg: &[u8]) -> Result<usize> {
    let egg_len = egg.len();
    let data_len = data.len();

    for i in 0..=data_len - egg_len {
        if data[i..i + egg_len] == *egg {
            if i + 4 + egg_len > data_len {
                return Err(Error::Custom("out-of-bounds read in egg hunting".to_string()))
            }
            if data[i + 4..i + 4 + egg_len] == *egg {
                return Ok(i);
            }
        }
    }

    Err(Error::Custom("egg was not found".to_string()))
}

pub(crate) fn run_command(cmd: &str, logname: &str) -> Result<()> {
    let log_path = Path::new("./logs").join(logname);

    let mut log_file = match File::create(&log_path) {
        Ok(log_file)    => log_file,
        Err(e)          => return_error!("run_command::File::create(log_file)::{e}")
    };

    wrap_message("debug", &format!("running command {}", cmd.to_string()));

    let mut command = Command::new("cmd");
    command.arg("/c").arg(cmd);

    let output = match command.output() {
        Ok(output)  => output,
        Err(e)      => return_error!("run_command::command.output()::{e}")
    };

    match log_file.write_all(&output.stdout) {
        Ok(_)   => { },
        Err(e)  => return_error!("run_command::log_file.write_all(stdout)::{e}")
    }

    match log_file.write_all(&output.stderr) {
        Ok(_)   => { },
        Err(e)  => return_error!("run_command::log_file.write_all(stderr)::{e}")
    }

    if !output.status.success() {
        return_error!("check {} for details", log_path.display());
    }

    Ok(())
}

pub(crate) fn create_directory(path: &str) -> Result<()> {
    match fs::create_dir_all(path) {
        Ok(_)   => { Ok(()) }
        Err(e)  => match e.kind() {
            ErrorKind::AlreadyExists    => Ok(()),
            _                           => Err(Io(e)),
        },
    }
}

pub fn source_to_outpath(source: String, outpath: &String) -> Result<String> {
    let source_path = Path::new(&source);

    let file_name = match source_path.file_name() {
        Some(name) => name,
        None => {
            eprintln!("Error: Could not extract file name from source: {}", source);
            return Err(io::Error::new(ErrorKind::InvalidInput, "Invalid source file").into());
        }
    };

    let mut output_path = PathBuf::from(&outpath);
    output_path.push(file_name);
    output_path.set_extension("o");

    let output_str = match output_path.to_str() {
        Some(output) => output.replace("/", "\\"),
        None => {
            eprintln!("Error: Could not convert output path to string");
            return Err(io::Error::new(ErrorKind::InvalidInput, "Invalid output path").into());
        }
    };

    Ok(output_str)
}

pub fn canonical_path(src_path: PathBuf) -> Result<Vec<PathBuf>> {
    let entries = fs::read_dir(&src_path)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| fs::canonicalize(entry.path()).ok())
        .collect();

    Ok(entries)
}

pub fn normalize_path(path_str: &str) -> String {
    let stripped_path = if path_str.starts_with(r"\\?\") || path_str.starts_with("//?/") {
        &path_str[4..]
    }
    else {
        path_str
    };

    stripped_path.replace("/", "\\")
}

pub fn generate_includes(includes: Vec<String>) -> String {
    includes.iter().map(|inc| format!(" -I{} ", inc)).collect::<Vec<_>>().join("")
}

pub fn generate_arguments(args: Vec<String>) -> String {
    args.iter().map(|arg| format!(" {} ", arg)).collect::<Vec<_>>().join("")
}

pub fn generate_definitions(definitions: &HashMap<String, Option<u8>>) -> String {
    let mut defs = String::new();

    for (name, def) in definitions {
        match def {
            None        => defs.push_str(&format!(" -D{} ", name)),
            Some(value) => defs.push_str(&format!(" -D{}={} ", name, value)),
        }
    }

    defs
}
