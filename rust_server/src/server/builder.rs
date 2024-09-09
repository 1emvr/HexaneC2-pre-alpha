use rayon::prelude::*;
use std::collections::HashMap;
use std::{env, fs};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::channel;
use crate::return_error;
use crate::server::error::{Error, Result};
use crate::server::binary::embed_section_data;
use crate::server::instance::Hexane;
use crate::server::utils::{run_command, wrap_message};
use crate::server::types::NetworkType;

pub fn generate_includes(includes: Vec<String>) -> String {
    wrap_message("debug", &"including directories".to_owned());
    includes.iter().map(|inc| format!(" -I{} ", inc)).collect::<Vec<_>>().join("")
}

pub fn generate_arguments(args: Vec<String>) -> String {
    wrap_message("debug", &"generating arguments".to_owned());
    args.iter().map(|arg| format!(" {} ", arg)).collect::<Vec<_>>().join("")
}

pub fn generate_definitions(definitions: HashMap<String, Vec<u8>>) -> String {
    let mut defs    = String::new();

    wrap_message("debug", &"generating defintions".to_owned());

    for (name, def) in definitions {
        if def.is_empty() {
            defs.push_str(&format!(" -D{} ", name));
        } else {
            defs.push_str(&format!(" -D{}={:?} ", name, def));
        }
    }

    defs
}

pub fn compile_object(instance: Hexane) -> Result<()> {

    if instance.main.debug {
        if instance.compiler.command != "ld" && instance.compiler.command != "nasm" {
            instance.definitions.insert("DEBUG".to_string(), vec![]);
        }
    }

    match instance.network_type {
        NetworkType::Http   => instance.definitions.insert("TRANSPORT_HTTP".to_string(), vec![]),
        NetworkType::Smb    => instance.definitions.insert("TRANSPORT_PIPE".to_string(), vec![]),
    }

    match instance.main.architecture {
        String::from("amd64") => instance.definitions.insert("BSWAP".to_string(), vec![0]),
        _ => instance.definitions.insert("BSWAP".to_string(), vec![1]),
    }

    if !instance.components.is_empty() {
        instance.command += &generate_arguments(instance.components.clone());
    }
    if !instance.flags.is_empty() {
        instance.command += &generate_arguments(instance.flags.clone());
    }

    for (k, v) in &instance.definitions {
        instance.command += &generate_definitions(HashMap::from([(k.clone(), v.clone())]));
    }

    instance.command += &format!(" -o {} ", instance.output_name);
    run_command(&instance.command, &instance.peer_id.to_string())?;

    wrap_message("debug", &"embedding config data".to_owned());
    embed_section_data(&instance.output_name, ".text$F", &instance.config_data.as_slice())?;
}

pub fn compile_sources(&self, root_directory: &str) -> Result<()> {
    let src_path        = Path::new(root_directory).join("src");
    let entries: Vec<_> = fs::read_dir(src_path)?.filter_map(|entry| entry.ok()).collect();

    let atoms = Arc::new(Mutex::new(()));
    let (err_send, err_recv) = channel();

    entries.par_iter().for_each(|src| {
        if !src.metadata().map_or(false, |m| m.is_file()) {
            return;
        }

        let path    = src.path();
        let output  = Path::new(&env::current_dir().unwrap().join("build")).join(self.output_name.clone()).with_extension("o");

        let atoms_clone     = Arc::clone(&atoms);
        let err_clone       = err_send.clone();
        let inc_clone       = self.includes.clone();
        let mut components  = self.components.clone();
        let def_clone       = self.definitions.clone();

        let result = {
            let _guard = atoms_clone.lock().unwrap();
            match path.extension().and_then(|ext| ext.to_str()) {

                Some("asm") => {
                    wrap_message("debug", &format!("compiling {}", &output.display()));

                    let flags = vec!["-f win64".to_string()];

                    let target = CompileTarget {
                        architecture:   "".to_string(),
                        command:        "nasm".to_string(),
                        output_name:    output.to_string_lossy().to_string(),
                        components:     vec![path.to_string_lossy().to_string()],
                        includes:       Some(vec![]),
                        network_type:   NetworkType::Http,
                        definitions:    HashMap::new(),
                        config_data:    self.config_data.clone(),
                        peer_id:        self.peer_id,
                        debug:          self.debug,
                        flags,
                    };

                    target.compile_object()
                }

                Some("cpp") => {
                    wrap_message("debug", &format!("compiling {}", &output.display()));

                    let mut flags = self.flags.clone();
                    flags.push("-c".to_string());

                    let target = CompileTarget {
                        command:        "x86_64-w64-mingw32-g++".to_string(),
                        output_name:    output.to_string_lossy().to_string(),
                        includes:       inc_clone,
                        definitions:    def_clone,
                        peer_id:        self.peer_id,
                        debug:          self.debug,
                        components:     vec![path.to_string_lossy().to_string()],
                        config_data:    vec![],
                        flags,
                        architecture: "".to_string(),
                        network_type: NetworkType::Http,
                    };

                    target.compile_object()
                }
                _ => Ok(()),
            }
        };

        match result {
            Ok(_) => components.push(output.to_str().unwrap().to_string()),
            Err(e) => err_clone.send(e).unwrap(),
        }
    });

    if let Ok(err) = err_recv.try_recv() {
        return_error!("{}", err);
    }

    Ok(())
}

