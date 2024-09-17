use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use pelite::{PeFile, pe32::headers::SectionHeader};
use crate::server::error::{Result, Error};
use crate::server::utils::{find_double_u32, read_file, wrap_message};
use crate::log_error;

struct Section {
    data:       Vec<u8>,
    section:    SectionHeader,
}

fn get_section_header (target_path: &str, target_section: &str) -> Result<Section> {
    let mut read_data = read_file(target_path)?;

    let pe_file = PeFile::from_bytes(&read_data)?;
    let mut found: Option<SectionHeader> = None;

    for entry in pe_file.section_headers() {
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
            log_error!("cannot find target section: {}", target_section);
            Err(Error::Custom("cannot find target section".to_string()))
        }
    }
}

pub(crate) fn copy_section_data(target_path: &str, out_path: &str, target_section: &str) -> Result<()> {
    let section_data = get_section_header(target_path, target_section)?;

    let offset  = section_data.section.PointerToRawData as usize;
    let size    = section_data.section.SizeOfRawData as usize;
    let data    = &section_data.data[offset..offset + size];

    let mut outfile = File::create(out_path)?;
    outfile.write_all(data)?;

    Ok(())
}

pub(crate) fn embed_section_data(target_path: &str, data: &[u8], sec_size: usize) -> Result<()> {
    let mut file_data   = read_file(target_path)?;
    let offset          = find_double_u32(&file_data, &[0x41,0x41,0x41,0x41])?;

    wrap_message("debug", &"embedding config data".to_string());

    if data.len() > sec_size {
        log_error!(&"data is longer than section size".to_string());
        return Err(Error::Custom("data is langer than target_section".to_string()))
    }

    file_data[offset..offset + data.len()].copy_from_slice(data);
    let mut read_file = OpenOptions::new().write(true).open(target_path)?;

    read_file.seek(SeekFrom::Start(offset as u64))?;
    read_file.write_all(&file_data)?;

    Ok(())
}


