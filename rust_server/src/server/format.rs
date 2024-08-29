use prettytable::{format, row, Cell, Row, Table};
use crate::server::INSTANCES;
use crate::server::types::{Loader, NetworkOptions};
use crate::server::error::{Result, Error};
use crate::server::instance::Hexane;

pub fn list_instances() -> Result<()> {
    let instances = INSTANCES.lock().map_err(|e| e.to_string())?;
    if instances.is_empty() {
        return Err(Error::Custom("No active implants available".to_string()))
    }

    let mut table = Table::new();
    table.set_titles(row!["gid", "pid", "name", "debug", "type", "address", "hostname", "domain", "proxy", "user", "active"]);

    for instance in instances.iter() {
        let (address, net_type, domain, proxy) = match &instance.network.options {

            NetworkOptions::Http(http) => {
                let address     = format!("{}:{}", http.address, http.port);
                let net_type    = "http".to_string();
                let domain      = http.domain.clone().unwrap_or_else(|| "null".to_string());

                let proxy = if let Some(proxy_config) = &http.proxy {
                    format!("{}://{}:{}", proxy_config.proto, proxy_config.address, proxy_config.port)
                } else {
                    "null".to_string()
                };

                (address, net_type, domain, proxy)
            }

            NetworkOptions::Smb(smb) => {
                let address     = smb.egress_peer.clone();
                let net_type    = "smb".to_string();
                (address, net_type, "null".to_string(), "null".to_string())
            }
        };

        table.add_row(row![
            instance.group_id.to_string(),
            instance.peer_id.to_string(),
            instance.builder.output_name,
            instance.main.debug.to_string(),
            net_type,
            address,
            instance.main.hostname,
            domain,
            proxy,
            instance.user_session.username,
            instance.active.to_string()
        ]);
    }

    table.printstd();
    Ok(())
}

    pub fn debug_hexane(instance: &Hexane) {
        // Print the main Hexane properties
        let mut hexane_table = Table::new();
        hexane_table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);

        hexane_table.add_row(Row::new(vec![Cell::new("Hexane Property"), Cell::new("Value")]));
        hexane_table.add_row(Row::new(vec![Cell::new("Current Task ID"), Cell::new(&instance.current_taskid.to_string())]));
        hexane_table.add_row(Row::new(vec![Cell::new("Peer ID"), Cell::new(&instance.peer_id.to_string())]));
        hexane_table.add_row(Row::new(vec![Cell::new("Group ID"), Cell::new(&instance.group_id.to_string())]));
        hexane_table.add_row(Row::new(vec![Cell::new("Build Type"), Cell::new(&instance.build_type.to_string())]));
        hexane_table.add_row(Row::new(vec![Cell::new("Crypt Key"), Cell::new(&format!("{:?}", instance.crypt_key))]));
        hexane_table.add_row(Row::new(vec![Cell::new("Shellcode"), Cell::new(&format!("{:?}", instance.shellcode))]));
        hexane_table.add_row(Row::new(vec![Cell::new("Config Data"), Cell::new(&format!("{:?}", instance.config_data))]));
        hexane_table.add_row(Row::new(vec![Cell::new("Network Type"), Cell::new(&instance.network_type.to_string())]));
        hexane_table.add_row(Row::new(vec![Cell::new("Active"), Cell::new(&instance.active.to_string())]));

        println!("Hexane Properties:");
        hexane_table.printstd();

        instance.print_config_table();
        instance.print_compiler_table();
        instance.print_network_table();
        instance.print_builder_table();

        if let Some(loader) = &instance.loader {
            loader.print_loader_table();
        } else {
            println!("Loader: None");
        }

        instance.print_user_session_table();
    }

    fn print_config_table(instance: &Hexane) {
        let mut config_table = Table::new();
        config_table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);

        config_table.add_row(Row::new(vec![Cell::new("Config Property"), Cell::new("Value")]));
        config_table.add_row(Row::new(vec![Cell::new("Debug"), Cell::new(&instance.main.debug.to_string())]));
        config_table.add_row(Row::new(vec![Cell::new("Encrypt"), Cell::new(&instance.main.encrypt.to_string())]));
        config_table.add_row(Row::new(vec![Cell::new("Architecture"), Cell::new(&instance.main.architecture)]));
        config_table.add_row(Row::new(vec![Cell::new("Hostname"), Cell::new(&instance.main.hostname)]));
        config_table.add_row(Row::new(vec![Cell::new("Working Hours"), Cell::new(&format!("{:?}", instance.main.working_hours))]));
        config_table.add_row(Row::new(vec![Cell::new("Kill Date"), Cell::new(&format!("{:?}", instance.main.killdate))]));
        config_table.add_row(Row::new(vec![Cell::new("Sleep Time"), Cell::new(&instance.main.sleeptime.to_string())]));
        config_table.add_row(Row::new(vec![Cell::new("Jitter"), Cell::new(&instance.main.jitter.to_string())]));

        println!("Config:");
        config_table.printstd();
    }

    fn print_compiler_table(instance: &Hexane) {
        let mut compiler_table = Table::new();
        compiler_table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);

        compiler_table.add_row(Row::new(vec![Cell::new("Compiler Property"), Cell::new("Value")]));
        compiler_table.add_row(Row::new(vec![Cell::new("File Extension"), Cell::new(&instance.compiler.file_extension)]));
        compiler_table.add_row(Row::new(vec![Cell::new("Build Directory"), Cell::new(&instance.compiler.build_directory)]));
        compiler_table.add_row(Row::new(vec![Cell::new("Compiler Flags"), Cell::new(&instance.compiler.compiler_flags)]));

        println!("Compiler:");
        compiler_table.printstd();
    }

    fn print_network_table(instance: &Hexane) {
        let mut network_table = Table::new();
        network_table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);

        network_table.add_row(Row::new(vec![Cell::new("Network Property"), Cell::new("Value")]));
        network_table.add_row(Row::new(vec![Cell::new("Type"), Cell::new("Http")]));

        if let NetworkOptions::Http(http) = &instance.network.options {
            network_table.add_row(Row::new(vec![Cell::new("Address"), Cell::new(&http.address)]));
            network_table.add_row(Row::new(vec![Cell::new("Port"), Cell::new(&http.port.to_string())]));
            network_table.add_row(Row::new(vec![Cell::new("Endpoints"), Cell::new(&format!("{:?}", http.endpoints))]));
            network_table.add_row(Row::new(vec![Cell::new("Domain"), Cell::new(&format!("{:?}", http.domain))]));
            network_table.add_row(Row::new(vec![Cell::new("User Agent"), Cell::new(&format!("{:?}", http.useragent))]));
            network_table.add_row(Row::new(vec![Cell::new("Headers"), Cell::new(&format!("{:?}", http.headers))]));
            network_table.add_row(Row::new(vec![Cell::new("Proxy"), Cell::new(&format!("{:?}", http.proxy))]));
        }

        println!("Network:");
        network_table.printstd();
    }

    fn print_builder_table(instance: &Hexane) {
        let mut builder_table = Table::new();
        builder_table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);

        builder_table.add_row(Row::new(vec![Cell::new("Builder Property"), Cell::new("Value")]));
        builder_table.add_row(Row::new(vec![Cell::new("Output Name"), Cell::new(&instance.builder.output_name)]));
        builder_table.add_row(Row::new(vec![Cell::new("Root Directory"), Cell::new(&instance.builder.root_directory)]));

        if let Some(linker_script) = &instance.builder.linker_script {
            builder_table.add_row(Row::new(vec![Cell::new("Linker Script"), Cell::new(linker_script)]));
        }

        if let Some(loaded_modules) = &instance.builder.loaded_modules {
            builder_table.add_row(Row::new(vec![Cell::new("Loaded Modules"), Cell::new(&format!("{:?}", loaded_modules))]));
        }

        builder_table.add_row(Row::new(vec![Cell::new("Dependencies"), Cell::new(&format!("{:?}", instance.builder.dependencies))]));
        builder_table.add_row(Row::new(vec![Cell::new("Include Directories"), Cell::new(&format!("{:?}", instance.builder.include_directories))]));

        println!("Builder:");
        builder_table.printstd();
    }

    fn print_user_session_table(instance: &Hexane) {
        let mut user_session_table = Table::new();
        user_session_table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);

        user_session_table.add_row(Row::new(vec![Cell::new("User Session Property"), Cell::new("Value")]));
        user_session_table.add_row(Row::new(vec![Cell::new("Username"), Cell::new(&instance.user_session.username)]));
        user_session_table.add_row(Row::new(vec![Cell::new("Is Admin"), Cell::new(&instance.user_session.is_admin.to_string())]));

        println!("User Session:");
        user_session_table.printstd();
    }

    fn print_loader_table(loader: &Loader) {
        let mut loader_table = Table::new();
        loader_table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);

        loader_table.add_row(Row::new(vec![Cell::new("Loader Property"), Cell::new("Value")]));
        loader_table.add_row(Row::new(vec![Cell::new("Root Directory"), Cell::new(&loader.root_directory)]));
        loader_table.add_row(Row::new(vec![Cell::new("Resource Script"), Cell::new(&loader.rsrc_script)]));

        loader_table.add_row(Row::new(vec![Cell::new("Injection Type"), Cell::new(&format!("{:?}", loader.injection.r#type))]));
        loader_table.add_row(Row::new(vec![Cell::new("Injection Options"), Cell::new(&format!("{:?}", loader.injection.options))]));

        loader_table.add_row(Row::new(vec![Cell::new("Sources"), Cell::new(&format!("{:?}", loader.sources))]));

        if let Some(linker_script) = &loader.linker_script {
            loader_table.add_row(Row::new(vec![Cell::new("Linker Script"), Cell::new(linker_script)]));
        }

        loader_table.add_row(Row::new(vec![Cell::new("Dependencies"), Cell::new(&format!("{:?}", loader.dependencies))]));

        println!("Loader:");
        loader_table.printstd();
    }