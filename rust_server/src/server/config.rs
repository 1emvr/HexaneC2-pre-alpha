use std::fs;
use crate::server::instance::Hexane;
use crate::server::error::{Result, Error};
use crate::server::types::{Compiler, JsonData, UserSession};
use crate::server::utils::wrap_message;
use crate::server::session::{CURDIR};


pub(crate) fn map_config(file_path: &String) -> Result<Hexane> {
    let json_file = CURDIR.join("json").join(file_path);
    let contents = fs::read_to_string(json_file).map_err(Error::Io)?;

    let json_data = match serde_json::from_str::<JsonData>(contents.as_str()) {
        Ok(data)    => data,
        Err(e)      => {
            wrap_message("debug", format!("{}", contents));
            return Err(Error::SerdeJson(e))
        }
    };

    // todo: group id selection
    let group_id = 0;
    let instance = Hexane {

        current_taskid: 0, peer_id: 0, group_id, build_type: 0, network_type: 0,
        crypt_key: vec![], shellcode: vec![], config_data: vec![],
        active: false,

        compiler: Compiler {
            file_extension:     "".to_owned(),
            build_directory:    "".to_owned(),
            compiler_flags:     "".to_owned(),
        },

        main:       json_data.config,
        network:    json_data.network,
        builder:    json_data.builder,
        loader:     json_data.loader,

        user_session: UserSession {
            username: "".to_owned(),
            is_admin: false,
        },
    };

    Ok(instance)
}


