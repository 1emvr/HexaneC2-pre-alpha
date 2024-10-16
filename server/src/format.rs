use prettytable::row;
use prettytable::Table;

use crate::interface::wrap_message;
use crate::rstatic::INSTANCES;
use crate::types::NetworkOptions;

pub fn list_instances() {
    let instances = INSTANCES
        .lock()
        .map_err(|e| e.to_string()).unwrap();

    if instances.is_empty() {
        wrap_message("error", &"No active implants available".to_string());
        return
    }

    let mut table = Table::new();
    table.set_titles(row!["gid", "pid", "name", "debug", "type", "callback", "hostname", "domain", "proxy", "user", "active"]);

    for instance in instances.iter() {

        let Some(network) = &instance.network_cfg else {
            wrap_message("error", &"list_instances: the network type did not match somehow".to_string());
            return
        };

        let (address, net_type, domain, proxy) = match &network.options {
            NetworkOptions::Http(http) => {
                let address     = format!("{}:{}", http.address, http.port);
                let net_type    = "http".to_string();
                let domain      = http.domain.clone().unwrap_or_else(|| "null".to_string());

                let proxy = if let Some(proxy_config) = &http.proxy {
                    format!("{}://{}:{}", proxy_config.proto, proxy_config.address, proxy_config.port)
                }
                else {
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
            instance.builder_cfg.output_name,
            instance.main_cfg.debug.to_string(),
            net_type,
            address,
            instance.main_cfg.hostname,
            domain,
            proxy,
            instance.user_session.username,
            instance.active.to_string()
        ]);
    }

    table.printstd();
}