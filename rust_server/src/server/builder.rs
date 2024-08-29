use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::channel;
use std::thread;

use crate::server::stream::Stream;
use crate::server::error::{Error, Result};
use crate::server::utils::{create_cpp_array, create_hash_macro, find_double_u32};
use crate::server::types::{Hexane, TRANSPORT_HTTP, TRANSPORT_PIPE};

pub(crate) const MINGW:     String = String::from("x86_64-w64-mingw32-g++");
pub(crate) const OBJCOPY:   String = String::from("objcopy");
pub(crate) const WINDRES:   String = String::from("windres");
pub(crate) const STRIP:     String = String::from("strip");
pub(crate) const NASM:      String = String::from("nasm");
pub(crate) const LINKER:    String = String::from("ld");

struct Module {
    root_directory: String,
    includes:       Option<Vec<String>>,
    definitions:    HashMap<String, Vec<u8>>,
    components:     Vec<String>,
}

fn generate_includes(includes: Vec<String>) -> String {
    includes.iter().map(|inc| format!(" -I{} ", inc)).collect::<Vec<_>>().join("")
}

fn generate_arguments(args: Vec<String>) -> String {
    args.iter().map(|arg| format!(" {} ", arg)).collect::<Vec<_>>().join("")
}

fn generate_definitions(defs: HashMap<String, Vec<u8>>) -> String {
    let mut definitions = String::new();

    for (name, def) in defs {
        let arr = create_cpp_array(&def, def.len());

        if def.is_empty() {
            definitions.push_str(&format!(" -D{} ", name));
        } else {
            definitions.push_str(&format!(" -D{}={:?} ", name, arr));
        }
    }

    definitions
}

fn compile_object(instance: &Hexane, mut command: String, output: &str, targets: Vec<String>, flags: Vec<String>, includes: Vec<String>, mut definitions: HashMap<String, Vec<u8>>) -> Result<()> {
    if definitions.is_empty() {
        definitions = HashMap::new();
    }

    if instance.main.debug && command != *LINKER {
        definitions.insert("DEBUG".to_string(), vec![]);
    }

    if !includes.is_empty() {
        command += &generate_includes(includes);
    }

    if !targets.is_empty() {
        command += &generate_arguments(targets);
    }

    if !flags.is_empty() {
        command += &generate_arguments(flags);
    }

    for (k, v) in definitions.iter() {
        command += &generate_definitions(HashMap::from([(k.clone(), v.clone())]));
    }

    command += &format!(" -o {} ", output);

    run_command(&command, &instance.peer_id.to_string())
}

fn embed_section_data(path: &str, data: &[u8], sec_size: usize) -> Result<()> {
    let mut read_file = OpenOptions::new().read(true).write(true).open(path)?;
    let mut read_data = Vec::new();

    read_file.read_to_end(&mut read_data)?;

    let offset = find_double_u32(&read_data, &[0x41, 0x41, 0x41, 0x41]).map_err({
        return Err(Error::Custom("pattern not found".to_string()))
    });

    if data.len() > sec_size {
        return Err(Error::Custom(format!("data is longer than {} bytes", sec_size)))
    }

    read_data[offset..offset + data.len()].copy_from_slice(data);

    if sec_size > data.len() {
        read_data[offset + data.len()..offset + sec_size].fill(0x00);
    }

    read_file.write_all(&read_data)?;
    Ok(())
}

fn copy_section_data(instance: &Hexane, path: &str, out: &str, target: &str) -> Result<()> {
    let read_file   = File::open(path)?;
    let pe_file     = pelite::File::parse(&read_file)?;
    let section     = pe_file.sections.iter().find(|s| s.name == target).map_err({
            return Err(Error::Custom("could not parse PE sections"))
    });

    let mut out_data = vec![0; section.size as usize];
    read_file.read_to_end(&mut out_data, section.pointer_to_raw_data as u64)?;

    fs::write(out, out_data)?;
    Ok(())
}


fn compile_sources(instance: &Hexane, module: &mut Module) -> Result<()> {
    let src_path    = Path::new(&module.root_directory).join("src");
    let entries     = fs::read_dir(src_path)?;

    let (sender, receiver) = channel();
    let arc_mux     = Arc::new(Mutex::new(()));
    let mut handles = vec![];

    for entry in entries {
        let src = entry?;

        if src.file_name() == ".idea" {
            continue;
        }

        let target  = src.path();
        let output  = Path::new("BuildPath").join(target.file_name().unwrap()).with_extension("o");

        let flags = match target.extension().and_then(|ext| ext.to_str()) {
            Some("asm") => vec!["-f win64".to_string()],
            Some("cpp") => {
                let mut flags = instance.compiler.compiler_flags.clone();
                flags.push("-c".to_string());
                flags
            }
            _ => continue,
        };

        let arc_mux_clone   = Arc::clone(&arc_mux);
        let sender_clone    = sender.clone();
        let mut components  = module.components.clone();

        let handle = thread::spawn(move || {
            let _guard = arc_mux_clone.lock().unwrap();

            let result = match target.extension().and_then(|ext| ext.to_str()) {
                Some("asm") => compile_object(instance, NASM, output.to_str().unwrap(), vec![target.to_str().unwrap().to_string()], flags, vec![], HashMap::new()),
                Some("cpp") => compile_object(instance, MINGW, output.to_str().unwrap(), vec![target.to_str().unwrap().to_string()], flags, module.includes.unwrap().clone(), module.definitions.clone()),
                _ => Ok(()),
            };

            match result {
                Ok(_) => components.push(output.to_str().unwrap().to_string()),
                Err(e) => sender_clone.send(e).unwrap(),
            }
        });

        handles.push(handle);
    }

    drop(sender);

    for handle in handles {
        handle.join().unwrap();
    }

    if let Ok(err) = receiver.try_recv() {
        return Err(err);
    }

    Ok(())
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
        return Err(Error::Custom(format!("check {} for details", log_path.display())));
    }

    Ok(())
}
