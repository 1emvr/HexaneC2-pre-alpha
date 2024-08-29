use prettytable::{format, row, Cell, Row, Table};
use crate::server::INSTANCES;
use crate::server::types::NetworkOptions;
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

pub fn hexane_debug(instance: &Hexane) {
    let mut table = Table::new();

    table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);

    table.add_row(Row::new(vec![Cell::new("Field"), Cell::new("Value")]));
    table.add_row(Row::new(vec![Cell::new("Current Task ID"), Cell::new(&instance.current_taskid.to_string())]));
    table.add_row(Row::new(vec![Cell::new("Peer ID"), Cell::new(&instance.peer_id.to_string())]));
    table.add_row(Row::new(vec![Cell::new("Group ID"), Cell::new(&instance.group_id.to_string())]));
    table.add_row(Row::new(vec![Cell::new("Build Type"), Cell::new(&instance.build_type.to_string())]));

    table.add_row(Row::new(vec![Cell::new("Crypt Key"), Cell::new(&format!("{:?}", instance.crypt_key))]));
    table.add_row(Row::new(vec![Cell::new("Shellcode"), Cell::new(&format!("{:?}", instance.shellcode))]));
    table.add_row(Row::new(vec![Cell::new("Config Data"), Cell::new(&format!("{:?}", instance.config_data))]));
    table.add_row(Row::new(vec![Cell::new("Network Type"), Cell::new(&instance.network_type.to_string())]));
    table.add_row(Row::new(vec![Cell::new("Active"), Cell::new(&instance.active.to_string())]));

    table.add_row(Row::new(vec![Cell::new("Main Config"), Cell::new(&format!("{:?}", instance.main))]));
    table.add_row(Row::new(vec![Cell::new("Compiler"), Cell::new(&format!("{:?}", instance.compiler))]));
    table.add_row(Row::new(vec![Cell::new("Network"), Cell::new(&format!("{:?}", instance.network))]));
    table.add_row(Row::new(vec![Cell::new("Builder"), Cell::new(&format!("{:?}", instance.builder))]));

    if let Some(loader) = &instance.loader {
        table.add_row(Row::new(vec![Cell::new("Loader"), Cell::new(&format!("{:?}", loader))]));
    } else {
        table.add_row(Row::new(vec![Cell::new("Loader"), Cell::new("None")]));
    }

    table.add_row(Row::new(vec![Cell::new("User Session"), Cell::new(&format!("{:?}", instance.user_session))]));
    table.printstd();
}