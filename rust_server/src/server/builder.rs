use std::collections::HashMap;
use std::{env, fs};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::channel;

use rayon::prelude::*;
use crate::server::instance::Hexane;
use crate::server::error::{Error, Result};
use crate::server::binary::embed_section_data;
use crate::server::utils::{run_command, wrap_message};
use crate::server::types::NetworkType;
use crate::return_error;

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

pub fn compile_object(mut instance: Hexane, flags: Vec<String> ) -> Result<()> {
    let mut defs: HashMap<String, Vec<u8>> = HashMap::new();

    if instance.compiler.command != "ld" && instance.compiler.command != "nasm" {
        if instance.main.debug {
            defs.insert("DEBUG".to_string(), vec![]);
        }

        match instance.main.architecture {
            String::from("amd64") => defs.insert("BSWAP".to_string(), vec![0]),
            _ => defs.insert("BSWAP".to_string(), vec![1]),
        }

        let Some(network) = &instance.network;

        if network.is_some() {
            match network.r#type {
                NetworkType::Http   => defs.insert("TRANSPORT_HTTP".to_string(), vec![]),
                NetworkType::Smb    => defs.insert("TRANSPORT_PIPE".to_string(), vec![]),
            }
        }
        else {
            return_error!("could not get network type during compilation")
        }
    }

    if !instance.compiler.components.is_empty() {
        instance.compiler.command += &generate_arguments(instance.compiler.components.clone());
    }
    if !flags.is_empty() {
        instance.compiler.command += &generate_arguments(flags);
    }

    for (k, v) in &defs {
        instance.compiler.command += &generate_definitions(HashMap::from([(k.clone(), v.clone())]));
    }

    instance.compiler.command += &format!(" -o {} ", instance.builder.output_name);
    run_command(&instance.compiler.command, &instance.peer_id.to_string())?;

    wrap_message("debug", &"embedding config data".to_owned());
    embed_section_data(&instance.builder.output_name, ".text$F", &instance.config_data.as_slice())?;
}

pub fn compile_sources(mut instance: Hexane) -> Result<()> {
    let src_path        = Path::new(&instance.builder.root_directory).join("src");
    let entries: Vec<_> = fs::read_dir(src_path)?.filter_map(|entry| entry.ok()).collect();

    let atoms = Arc::new(Mutex::new(()));
    let (err_send, err_recv) = channel();

    entries.par_iter().for_each(|src| {
        if !src.metadata().map_or(false, |map| map.is_file()) {
            return;
        }

        let path    = src.path();
        let output  = Path::new(&env::current_dir().unwrap().join("build")).join(instance.builder.output_name.clone()).with_extension("o");

        let atoms_clone = Arc::clone(&atoms);
        let err_clone   = err_send.clone();

        let result = {
            let _guard = atoms_clone.lock().unwrap();
            match path.extension().and_then(|ext| ext.to_str()) {

                Some("asm") => {
                    let flags = vec!["-f win64".to_string()];

                    wrap_message("debug", &format!("compiling {}", &output.display()));
                    compile_object(instance, flags)?;
                }

                Some("cpp") => {
                    let mut flags = vec![instance.compiler.compiler_flags.clone()];
                    flags.push("-c".parse().unwrap());

                    wrap_message("debug", &format!("compiling {}", &output.display()));
                    compile_object(instance, flags)?;
                }
                _ => {
                }
            }
        };

        match result {
            Ok(_)   => instance.components.push(output.to_str().unwrap().to_string()),
            Err(e)  => err_clone.send(e).unwrap(),
        }
    });

    if let Ok(err) = err_recv.try_recv() {
        return_error!("{}", err);
    }

    Ok(())
}

