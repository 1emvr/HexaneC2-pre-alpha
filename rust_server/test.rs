/*
fn check_config(&mut self) -> Result<()> {
    if self.main.hostname.is_empty()                    { return_error!("a valid hostname must be provided") }
    if self.main.architecture.is_empty()                { return_error!("a valid architecture must be provided") }
    if self.main.jitter < 0 || self.main.jitter > 100   { return_error!("jitter cannot be less than 0% or greater than 100%") }
    if self.main.sleeptime < 0                          { return_error!("sleeptime cannot be less than zero. wtf are you doing?") }

    if self.builder.output_name.is_empty()              { return_error!("a name for the build must be provided") }
    if self.builder.root_directory.is_empty()           { return_error!("a root directory for implant files must be provided") }

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

            // todo: proxy should not be exclusive to http (socks5, ftp, smtp etc)
            if let Some(proxy) = &http.proxy {
                if proxy.proto.is_empty()               { return_error!("proxy protocol must be provided") }
                if proxy.address.is_empty()             { return_error!("proxy field detected but proxy address must be provided") }
                if proxy.port < 0 || proxy.port > 65535 { return_error!("proxy field detected but proxy port must be between 0-65535") }

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



 */