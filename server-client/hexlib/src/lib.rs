pub mod error;
pub mod parser;
pub mod stream;
pub mod types;

use crate::error::{Result, Error};
use serde::ser::{Serialize, Serializer, SerializeStruct};

pub fn json_serialize<T: Serialize>(data: T) -> Result<String> {
    let json = match serde_json::to_string(&data) {
        Ok(json) => json,
        Err(e) => {
            println!("[ERR] error serializing data to json");
            return Err(Error::SerdeJson(e))
        }
    };

    Ok(json)
}

pub fn json_deserialize(data: String) -> String {
	serde_json::from_str(data.as_str()).unwrap()
}
