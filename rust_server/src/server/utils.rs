use std::fs::File;
use crossbeam_channel::{select};
use colored::*;

use std::{fs, io};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::Command;

use crate::return_error;
use crate::server::session::{CHANNEL, DEBUG, EXIT};
use crate::server::error::{Error, Result};
use crate::server::types::{Message};
use crate::server::stream::Stream;

pub fn cursor() {
    print!(" > ");
    io::stdout().flush().unwrap();
}

pub(crate) fn get_embedded_strings(str_list: Vec<String>) -> Vec<u8> {
    let mut stream = Stream::new();
    for s in str_list {
        stream.pack_string(&s);
    }

    stream.buffer
}

pub(crate) fn create_cpp_array(buffer: &[u8], length: usize) -> Vec<u8> {
    let mut array = String::from("{");

    for (i, &byte) in buffer.iter().enumerate() {
        if i == length - 1 {
            array += &format!("0x{:02X}", byte);
        } else {
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
    } else {
        (lower.into_bytes(), false)
    };

    format!(
        "#define {} 0x{:x}",
        macro_name.split('.').next().unwrap(),
        crate::server::cipher::get_hash_from_string(&String::from_utf8_lossy(&name), is_unicode)
    )
}

fn generate_hashes(strings_file: &str, out_file: &str) -> Result<()> {
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
                        "error" => format!("{}", m.msg_type.red()),
                        _       => m.msg_type,
                    };
                    println!("[{}] {}", fmt_msg, m.msg);
                    cursor();
                }
            }
        }
    }
}

pub fn wrap_message(typ: &str, msg: String) {
    let sender = &CHANNEL.0;
    let message = Message { msg_type: typ.to_string(), msg: msg.to_string(),};

    sender.send(message).unwrap();
}

pub fn stop_print_channel() {
    let sender = &EXIT.0;
    sender.send(()).unwrap();
}

fn encode_utf16(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect()
}

fn run_command(cmd: &str, logname: &str) -> Result<()> {
    let shell   = if cfg!(target_os = "windows") { "cmd" } else { "bash" };
    let flag    = if cfg!(target_os = "windows") { "/c" } else { "-c" };

    let log_path = Path::new("LogsPath").join(logname);
    let mut log_file = File::create(&log_path)?;

    let mut command = Command::new(shell);
    command.arg(flag).arg(cmd);

    let output = command.output()?;

    log_file.write_all(&output.stdout)?;
    log_file.write_all(&output.stderr)?;

    if !output.status.success() {
        return_error!("check {} for details", log_path.display());
    }

    Ok(())
}
