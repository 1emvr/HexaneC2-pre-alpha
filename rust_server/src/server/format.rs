use prettytable::{row, Table};
use crate::server::INSTANCES;
use crate::server::types::NetworkOptions;
use crate::server::error::{Result, Error};

pub fn list_instances() -> Result<()> {
    let instances = INSTANCES.lock().map_err(|e| e.to_string())?;
    let mut table = Table::new();

    table.set_titles(row!["gid", "pid", "name", "debug", "type", "address", "hostname", "domain", "proxy", "user", "active"]);

    if instances.is_empty() {
        return Err(Error::Custom("No active implants available".to_string()))
    }

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
