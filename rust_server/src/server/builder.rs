use std::collections::HashMap;
use std::path::{Path};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::channel;
use std::{env, thread};
use std::fs;
use crate::return_error;
use crate::server::error::{Result};
use crate::server::session::CURDIR;
use crate::server::utils::{create_cpp_array, run_command};
use crate::server::types::{Hexane};

pub(crate) const MINGW:     String = String::from("x86_64-w64-mingw32-g++");
pub(crate) const OBJCOPY:   String = String::from("objcopy");
pub(crate) const WINDRES:   String = String::from("windres");
pub(crate) const STRIP:     String = String::from("strip");
pub(crate) const NASM:      String = String::from("nasm");
pub(crate) const LINKER:    String = String::from("ld");

struct CompileTarget {
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

// todo: define build path and logs path
fn compile_sources(instance: &Hexane, compile: &mut CompileTarget) -> Result<()> {

    let src_path    = Path::new(&compile.root_directory).join("src");
    let entries     = fs::read_dir(src_path)?;

    let atoms                   = Arc::new(Mutex::new(()));
    let (err_send, err_recv)    = channel();
    let mut handles             = vec![];

    for entry in entries {
        let src = entry?;
        if !src.metadata()?.is_file() {
            continue;
        }

        let path    = src.path();
        let output  = Path::new(&env::current_dir()? +"/build").join(compile.file_name().unwrap()).with_extension("o");

        let flags = match path.extension().and_then(|ext| ext.to_str()) {
            Some("asm") => vec!["-f win64".to_string()],
            Some("cpp") => {
                let mut flags = instance.compiler.compiler_flags.clone();
                flags.push_str("-c".to_str());
                flags
            },
            _ => continue,
        };

        let atoms_clone     = Arc::clone(&atoms);
        let err_clone  = err_send.clone();

        let includes        = compile.includes.clone();
        let mut components  = compile.components.clone();

        // todo: does this really need to be multithreaded?
        let handle = thread::spawn(move || {
            let _guard = atoms_clone.lock().unwrap();

            // todo: add config file extension
            let result = match compile.extension().and_then(|ext| ext.to_str()) {
                Some("asm") => compile_object(instance, "nasm", output.to_str().unwrap(), vec![path], flags, vec![], HashMap::new()),
                Some("cpp") => compile_object(instance, "x86_64-w64-mingw32-g++", output.to_str().unwrap(), vec![path], flags, includes.unwrap(), &compile.definitions),
                _ => Ok(())
            };

            match result {
                Ok(_)   => components.push(output.to_str().unwrap().to_string()),
                Err(e)  => err_clone.send(e).unwrap(),
            }
        });

        handles.push(handle);
    }

    drop(err_send);

    for handle in handles {
        handle.join().unwrap();
    }

    if let Ok(err) = err_recv.try_recv() {
        return_error!("{}" ,err);
    }

    Ok(())
}

