use std::fs;
use std::io::{Read, Write};
use std::fs::{File, OpenOptions};
use std::process::Command;
use std::path::Path;

use pe_parser;
use pe_parser::pe::parse_portable_executable;

use crate::interface::wrap_message;
use crate::utils::{find_double_u32, read_file};

use crate::error::Error::Custom as Custom;
use crate::error::Result as Result;

struct Section {
    data: Vec<u8>,
    size: usize,
}

fn get_text_section(target_path: &str) -> Result<Section> {
    let read_data = read_file(target_path)
        .map_err(|e| {
            wrap_message("ERR", format!("get_text_section: {target_path} : error reading target file").as_str());
            return Custom(e.to_string())
        })?;

    let pe_file = parse_portable_executable(&read_data)
        .map_err(|e| {
            wrap_message("ERR", "get_text_section: error converting target file");
            return Custom(e.to_string())
        });

    let opt_head = pe_file
        .unwrap()
        .optional_header_64;

    let head_size = opt_head.unwrap().size_of_headers as usize;
    let code_size = opt_head.unwrap().size_of_code as usize;

    let mut data = Vec::new();
    data.append(read_data[head_size .. head_size + code_size].to_vec().as_mut());

    Ok(Section {
        data: data,
        size: code_size,
    })
}

pub(crate) fn extract_section(target_path: &str, config: &[u8], output_file: &str) -> Result<()> {
    let mut section = get_text_section(target_path)
        .map_err(|e| {
            wrap_message("ERR", format!("extract_section : {e}").as_str());
            return Custom(e.to_string())
        })?;

    let offset = find_double_u32(&section.data, &[0xaa,0xaa,0xaa,0xaa])
        .map_err(|e| {
            wrap_message("ERR", format!("extract_section : {e}").as_str());
            return Custom(e.to_string());
        })?;


    if offset + config.len() > section.size {
        wrap_message("ERR", "extract_section: config is longer than section size");
        return Err(Custom("ConfigError".to_string()))
    }

    section.data[offset..offset + config.len()].copy_from_slice(config);

    let mut output = OpenOptions::new().write(true).create(true).open(output_file)
        .map_err(|e| {
            wrap_message("ERR", format!("extract_section: error opening output file: {output_file} : {e}").as_str());
            return Custom(e.to_string());
        })?;

    output.write_all(&section.data)
        .map_err(|e| {
            wrap_message("ERR", format!("extract_section: {:?} : error writing file config: {e}", output).as_str());
            return Custom(e.to_string())
        })?;

    Ok(())
}

pub(crate) fn run_command(cmd: &str, logname: &str) -> Result<()> {
    let log_dir = Path::new("./logs");

    if !log_dir.exists() {
        fs::create_dir_all(&log_dir)
            .map_err(|e| {
                wrap_message("ERR", format!("run_command:: create_dir_all: {e}").as_str());
                return Custom(e.to_string())
            })?;
    }

    let mut log_file = File::create(&log_dir.join(logname))
        .map_err(|e| {
            wrap_message("ERR", format!("run_command: file::create: {e}").as_str());
            return Custom(e.to_string())
        })?;

    // TODO: show commands in errors instead of a debug message
    wrap_message("INF", format!("running command: {cmd}").as_str());

    let mut command = Command::new("powershell");
    command.arg("-c").arg(cmd);

    let output = command.output()
        .map_err(|e| {
            wrap_message("ERR", format!("run_command: {e}").as_str());
            return Custom(e.to_string())
        })?;

    if !&output.stderr.is_empty() {

        log_file.write_all(&output.stderr)
            .map_err(|e| {
                wrap_message("ERR", format!("run_command: {e}").as_str());
                return Custom(e.to_string())
            })?;

        wrap_message("ERR", &format!("run_command: check {}/{} for details", log_dir.display(), logname));
        return Err(Custom("run command failed".to_string()))
    }

    match output.status.success() {
        true => Ok(()),
        false => {
            wrap_message("ERR", "running command failed");
            Err(Custom("run command failed".to_string()))
        }
    }
}

