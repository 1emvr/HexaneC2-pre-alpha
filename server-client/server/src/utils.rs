use crate::error::Result as Result;
use crate::error::Error::Custom as Custom;

use crate::stream::Stream as Stream;
use crate::types::NetworkType::Http as HttpType;
use crate::types::NetworkType::Smb as SmbType;
use crate::types::{Config, Network};


use std::fs::File;
use std::{ env, fs };
use std::io::{ Read, BufRead, BufReader };

use std::collections::HashMap;
use std::path::{ Path, PathBuf };


pub const FNV_OFFSET:   u32 = 2166136261;
pub const FNV_PRIME:    u32 = 16777619;


pub(crate) fn read_file(target_path: &str) -> Result<Vec<u8>>{
    let mut read_data = Vec::new();
    let mut read_file = File::open(target_path)?;

    read_file.read_to_end(&mut read_data)?;
    Ok(read_data)
}

pub(crate) fn get_embedded_strings(str_list: Vec<String>) -> Vec<u8> {
    let mut stream = Stream::new();

    for string in str_list {
        stream.pack_string(&string);
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

pub(crate) fn get_hash_from_string(string: &str) -> u32 {
    let mut hash = FNV_OFFSET;

    for i in 0..string.len() {
        hash ^= string.as_bytes()[i] as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    hash
}

fn create_hash_macro(input: &str) -> String {
    let hash = get_hash_from_string(input.to_lowercase().as_str());

    let name = input.trim();
    let collection: Vec<&str> = name.split('.').collect();

    let first = collection.get(0).unwrap_or(&"").trim_matches('"');
    let second = collection.get(1).unwrap_or(&"").trim_matches('"');

    let macro_name = if first.is_empty() {
        second
    } else {
        first
    };

    format!("#define {} 0x{:x}", macro_name.to_uppercase(), hash)
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

    for i in 0..= data_len - egg_len {
        if data[i..i + egg_len] == *egg {

            if i + 4 + egg_len > data_len {
                return Err(Custom("out-of-bounds read in egg hunting".to_string()))
            }
            if data[i + 4..i + 4 + egg_len] == *egg {
                return Ok(i);
            }
        }
    }

    Err(Custom("egg was not found".to_string()))
}

pub fn source_to_outpath(source: String, outpath: &String) -> Result<String> {
    let source_path = Path::new(&source);

    let file_name = match source_path.file_name() {
        Some(name) => name,
        None => {
            return Err(Custom(format!("could not extract file name from source: {source}")))
        }
    };

    let mut output_path = PathBuf::from(&outpath);

    output_path.push(file_name);
    output_path.set_extension("o");

    let output_str = match output_path.to_str() {
        Some(output) => output.replace("/", "\\"),
        None => {
            return Err(Custom(format!("could not convert output path to string: {}", output_path.display())))
        }
    };

    Ok(output_str)
}

pub fn canonical_path_all(src_path: &Path) -> Result<Vec<PathBuf>> {
    let entries = fs::read_dir(&src_path)
        .map_err(|e| Custom(format!("canonical_path_all: {e}")))?;

    let all = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .collect();

    Ok(all)
}

pub fn normalize_path(path_string: String) -> String {
    let stripped_path = if path_string.starts_with(r"\\?\") || path_string.starts_with("//?/") {
        &path_string[4..]
    }
    else {
        &*path_string
    };

    stripped_path.replace("/", "\\")
}

pub fn generate_object_path(source_path: &str, build_dir: &Path) -> Result<PathBuf> {
    if let Some(filename) = Path::new(source_path)
        .file_name() {
            filename
                .to_string_lossy()
                .to_string()
                .push_str(".o");

            Ok(build_dir.join(filename))
    }
    else {
        return Err(Custom("generate_object_path: ??".to_string()))
    }
}

pub fn generate_definitions(main_cfg: &Config, network_cfg: &Network) -> String {
    let mut defs: HashMap<String, Option<u32>> = HashMap::new();

    let config_size = main_cfg.config_size;
    let encrypt     = main_cfg.encrypt;
    let arch        = &main_cfg.architecture;

    // need to be set as Option<> because some defs don't have values (see below)
    let size_def    = Some(config_size);
    let enc_def     = Some(if encrypt { 1 } else { 0 });
    let bswap_def   = Some(if arch == "amd64" { 1 } else { 0 });

    defs.insert("CONFIG_SIZE".to_string(), size_def);
    defs.insert("ENCRYPTED".to_string(), enc_def);
    defs.insert("BSWAP".to_string(), bswap_def);

    if main_cfg.debug {
        defs.insert("DEBUG".to_string(), None);
    }

    // detect network type
    match network_cfg.r#type {
        HttpType => { defs.insert("TRANSPORT_HTTP".to_string(), None); }
        SmbType => { defs.insert("TRANSPORT_PIPE".to_string(), None); }
    }

    // set defs
    let definitions: Vec<String> = defs.iter()
        .map(|(name, def)| {
            if let Some(value) = def {
                format!(" -D{}={}", name, value)
            } else {
                format!(" -D{}", name)
            }
        }).collect();

    definitions.join(" ")
}

pub fn generate_includes(include_directories: &Vec<String>) -> String {
    let current = env::current_dir()
        .unwrap()
        .canonicalize();

    let path = normalize_path(current
        .unwrap()
        .display()
        .to_string()
    );

    let mut user_include    = vec![path.to_owned()];
    let mut includes        = vec![];
    let mut paths           = vec![];

    for inc_path in include_directories {
        paths.push(normalize_path(inc_path.to_owned()));
    }

    user_include.extend(paths);

    for path in user_include.iter() {
        includes.push(format!(" -I\"{}\" ", path))
    }

    includes.join(" ")
}

pub fn generate_arguments(args: Vec<String>) -> String {
    args.iter()
        .map(|arg| format!(" {} ", arg))
        .collect::<Vec<_>>()
        .join("")
}

fn encode_utf16(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect()
}

pub fn print_help() -> String {
    format!(r#"
Available Commands:

General:
  exit        - Exit the application
  help        - Display this help message

Implant Management:
  implant ls       - List all loaded implants
  implant load     - Load an implant from a specified configuration
  implant rm       - Remove a loaded implant

Listener Management:
  listener attach  - Attach to a listener associated with an implant (not implemented)

"#)
}

