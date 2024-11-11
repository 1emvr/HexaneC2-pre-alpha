use pe_parser::pe::parse_portable_executable;

use std::fs::{ File, OpenOptions };
use std::process::Command;
use std::path::Path;
use std::io::Write;
use std::fs;

use crate::utils::{ find_double_u32, read_file };
use crate::error::Error::Custom as Custom;
use crate::error::Result as Result;

struct Section {
    data: Vec<u8>,
    size: usize,
}

fn get_text_section(target_path: &str) -> Result<Section> {
    let read_data = read_file(target_path)
        .map_err(|e| format!("get_text_section: {target_path}: error reading target file: {e}"))?;

    let pe_file = parse_portable_executable(&read_data)
        .map_err(|e| format!("get_text_section: error converting target file: {e}"));

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
        .map_err(|e| Custom(format!("extract_section : {e}")))?;

    let offset = find_double_u32(&section.data, &[0xaa,0xaa,0xaa,0xaa])
        .map_err(|e| Custom(format!("extract_section : {e}")))?;


    if offset + config.len() > section.size {
        return Err(Custom("extract_section: config is longer than section size".to_string()))
    }

    section.data[offset..offset + config.len()].copy_from_slice(config);

    let mut output = OpenOptions::new().write(true).create(true).open(output_file)
        .map_err(|e| Custom(format!("extract_section: error opening output file: {output_file} : {e}")))?;

    output.write_all(&section.data)
        .map_err(|e| Custom(format!("extract_section: {:?} : error writing file config: {e}", output)))?;

    Ok(())
}

pub(crate) fn run_command(cmd: &str, logname: &str) -> Result<()> {
    let log_dir = Path::new("./logs");

    if !log_dir.exists() {
        fs::create_dir_all(&log_dir)
            .map_err(|e| Custom(format!("run_command:: create_dir_all: {e}")))?;
    }

    let mut log_file = File::create(&log_dir.join(logname))
        .map_err(|e| Custom(format!("run_command: file::create: {e}")))?;

    let mut command = match std::env::consts::OS {
        "windows" => Command::new("powershell"),
        "linux"   => Command::new("bash"),
        _ => {
            return Err(Custom("unknown OS".to_string()));
        }
    };

    command.arg("-c").arg(cmd);

    let output = command.output()
        .map_err(|e| Custom(format!("run_command: {e}")))?;

    if !&output.stderr.is_empty() {

        log_file.write_all(&output.stderr)
            .map_err(|e| Custom(format!("run_command: {e}")))?;

        return Err(Custom(format!("run_command: check {}/{} for details", log_dir.display(), logname)))
    }

    match output.status.success() {
        true => Ok(()),
        false => {
            return Err(Custom("running command failed".to_string()))
        }
    }
}

