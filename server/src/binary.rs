use std::io::Write;
use std::fs::{File, OpenOptions};
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
            wrap_message("ERR", "get_section_header: error reading target file");
            return Custom(e.to_string())
        });

    let pe_file = PeFile::from_bytes(&read_data.unwrap())
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

pub(crate) fn copy_section_data(target_path: &str, out_path: &str, target_section: &str) -> Result<()> {
    let section_data = get_section_header(target_path, target_section)
        .map_err(|e| {
            return Custom(e.to_string())
        })
        .unwrap();

    let offset  = section_data.section.PointerToRawData as usize;
    let size    = section_data.section.SizeOfRawData as usize;
    let data    = &section_data.data[offset..offset + size];

    let mut outfile = File::create(out_path)
        .map_err(|e| {
            wrap_message("ERR", "copy_section_data: error creating output file");
            return Custom(e.to_string())
        })
        .unwrap();

    outfile.write_all(data)
        .map_err(|e| {
            wrap_message("ERR", "copy_section_data: error writing to output file");
            return Custom(e.to_string())
        })
        .unwrap();

    Ok(())
}

pub(crate) fn embed_section_data(target_path: &str, data: &[u8], sec_size: usize) -> Result<()> {
    let mut file_data = read_file(target_path)
        .map_err(|e| {
            wrap_message("ERR", format!("embed_section_data: error reading target file: {e}").as_str());
            return Custom(e.to_string());
        });

    let offset = find_double_u32(&file_data.unwrap(), &[0x41,0x41,0x41,0x41])?;

    if data.len() > sec_size || data.len() + offset > sec_size {
        wrap_message("ERR", "data is longer than section size");
        return Err(Custom("fuck off".to_string()))
    }

    wrap_message("INF", "embedding config data");
    file_data[offset..offset + data.len()].copy_from_slice(data);

    let mut output = OpenOptions::new().write(true).open(target_path)
        .map_err(|e| {
            wrap_message("ERR", format!("embed_section_data: error opening output file: {e}").as_str());
            return Custom(e.to_string());
        });

    output.unwrap().write_all(&file_data)
        .map_err(|e| {
            wrap_message("ERR", format!("embed_section_data: error writing file data: {e}").as_str());
            return Custom(e.to_string())
        })
        .expect("what in the fuck?");

    Ok(())
}


