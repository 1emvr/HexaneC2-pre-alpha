use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::channel;
use rayon::prelude::*;
use std::env;
use std::fs;

use crate::return_error;
use crate::server::error::Result;
use crate::server::utils::{create_cpp_array, run_command};

struct CompileTarget {
    command:        String,
    root_directory: String,
    output_name:    String,
    components:     Vec<String>,
    flags:          Vec<String>,
    includes:       Option<Vec<String>>,
    definitions:    HashMap<String, Vec<u8>>,
    peer_id:        u32,
    debug:          bool,
}
impl CompileTarget {

    fn compile_sources(self) -> Result<()> {
        let src_path                = Path::new(&self.root_directory).join("src");
        let entries: Vec<_>         = fs::read_dir(src_path)?.filter_map(|entry| entry.ok()).collect();

        let atoms                   = Arc::new(Mutex::new(()));
        let (err_send, err_recv)    = channel();

        entries.par_iter().for_each(|src| {
            if !src.metadata().map_or(false, |m| m.is_file()) {
                return;
            }

            let path = src.path();
            let output = Path::new(&env::current_dir().unwrap().join("build")).join(self.output_name.clone()).with_extension("o");

            let atoms_clone     = Arc::clone(&atoms);
            let err_clone       = err_send.clone();
            let inc_clone       = self.includes.clone();
            let mut components  = self.components.clone();
            let def_clone       = self.definitions.clone();

            let result = {
                let _guard = atoms_clone.lock().unwrap();
                match path.extension().and_then(|ext| ext.to_str()) {

                    Some("asm") => {
                        let flags = vec!["-f win64".to_string()];

                        let target = CompileTarget {
                            command:        "nasm".to_string(),
                            root_directory: "".to_string(),
                            output_name:    output.to_string_lossy().to_string(),
                            components:     vec![path.to_string_lossy().to_string()],
                            includes:       Some(vec![]),
                            definitions:    HashMap::new(),
                            peer_id:        self.peer_id,
                            debug:          self.debug,
                            flags,
                        };

                        target.compile_object()
                    }

                    Some("cpp") => {
                        let mut flags = self.flags.clone();
                        flags.push("-c".to_string());

                        let target = CompileTarget {
                            command:        "x86_64-w64-mingw32-g++".to_string(),
                            root_directory: "".to_string(),
                            output_name:    output.to_string_lossy().to_string(),
                            components:     vec![path.to_string_lossy().to_string()],
                            includes:       inc_clone,
                            definitions:    def_clone,
                            peer_id:        self.peer_id,
                            debug:          self.debug,
                            flags,
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

    fn compile_object(mut self) -> Result<()> {
        if self.debug && self.command != "ld" && self.command != "nasm" {
            self
                .definitions
                .insert("DEBUG".to_string(), vec![]);
        }

        if let Some(includes) = &self.includes {
            if !includes.is_empty() {
                self.command += &generate_includes(includes.clone());
            }
        }

        if !self.components.is_empty() {
            self.command += &generate_arguments(self.components.clone());
        }

        if !self.flags.is_empty() {
            self.command += &generate_arguments(self.flags.clone());
        }

        for (k, v) in &self.definitions {
            self.command += &generate_definitions(HashMap::from([(k.clone(), v.clone())]));
        }

        self.command += &format!(" -o {} ", self.output_name);

        run_command(&self.command, &self.peer_id.to_string())
    }
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

