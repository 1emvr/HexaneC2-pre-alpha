use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use pelite::{PeFile, pe32::headers::SectionHeader};

use crate::return_error;
use crate::server::error::{Result, Error};
use crate::server::utils::{find_double_u32, wrap_message};

struct Section {
    data:       Vec<u8>,
    section:    SectionHeader,
}

fn get_section_header (target_path: &str, target_section: &str) -> Result<Section> {
    let mut read_data = Vec::new();
    let mut read_file = File::open(target_path)?;

    read_file.read_to_end(&mut read_data)?;

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
        None => return_error!("cannot find target section: {target_section}")
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

pub(crate) fn embed_section_data(target_path: &str, target_section: &str, data: &[u8]) -> Result<()> {
    let mut section_data    = get_section_header(target_path, target_section)?;
    let offset              = find_double_u32(&section_data.data, &[0x41,0x41,0x41,0x41])?;
    let size                = section_data.section.SizeOfRawData;

    wrap_message("debug", &format!("embedding config data to {target_section}"));

    if data.len() > size as usize {
        return_error!(format!("data is longer than {target_section}.SizeOfRawData"))
    }

    if offset + data.len() > size as usize {
        return_error!("data is too long from the offset. This would write outside of the section")
    }

    section_data.data[offset..offset + data.len()].copy_from_slice(data);

    let mut read_file = OpenOptions::new().write(true).open(target_path)?;
    read_file.seek(SeekFrom::Start(section_data.section.PointerToRawData as u64))?;
    read_file.write_all(&section_data.data)?;

    Ok(())
}

