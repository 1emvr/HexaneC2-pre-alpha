use std::fs;
use std::io::Write;
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::process::Command;
use pelite::{PeFile, pe32::headers::SectionHeader};

use crate::interface::wrap_message;
use crate::utils::{find_double_u32, read_file};

use crate::error::Error::Custom as Custom;
use crate::error::Result as Result;

struct Section {
    data:       Vec<u8>,
    section:    SectionHeader,
}

fn get_section_header (target_path: &str, target_section: &str) -> Result<Section> {
    let read_data = read_file(target_path)
        .map_err(|e| {
            wrap_message("ERR", format!("get_section_header: {target_path} : error reading target file").as_str());
            return Custom(e.to_string())
        })?;

    let pe_file = PeFile::from_bytes(&read_data)
        .map_err(|e| {
            wrap_message("ERR", "get_section_header: error converting target file");
            return Custom(e.to_string())
        });

    let mut found: Option<SectionHeader> = None;

    for entry in pe_file?.section_headers() {
        if entry.name()?.to_string() == target_section {
            found = Some(entry.clone());
            break;
        }
    }

    match found {
        Some(section_header) => Ok(Section {
            data:       read_data,
            section:    section_header,
        }),

        None => {
            wrap_message("ERR", format!("cannot find target section: {}", target_section).as_str());
            Err(Custom("cannot find target section".to_string()))
        }
    }
}

pub(crate) fn extract_section_data(target_path: &str, target_section: &str, config: &[u8], output_file: &str) -> Result<()> {
    let mut section_data = get_section_header(target_path, target_section)
        .map_err(|e| {
            return Custom(e.to_string())
        })?;

    let offset  = find_double_u32(&section_data.data, &[0xaa,0xaa,0xaa,0xaa])?;
    let size    = section_data.section.SizeOfRawData as usize;

    if config.len() > size || offset + config.len() > size {
        wrap_message("ERR", "config is longer than section size");
        return Err(Custom("ConfigError".to_string()))
    }

    section_data.data[offset..offset + config.len()].copy_from_slice(config);

    let mut output = OpenOptions::new().write(true).create(true).open(output_file)
        .map_err(|e| {
            wrap_message("ERR", format!("extract_section_data: error opening output file: {output_file} : {e}").as_str());
            return Custom(e.to_string());
        })?;

    output.write_all(&section_data.data)
        .map_err(|e| {
            wrap_message("ERR", format!("extract_section_data: {:?} : error writing file config: {e}", output).as_str());
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

