use crate::types::HexaneStream;
use lazy_static::lazy_static;

type ConfigStore = Arc<Mutex<Vec<HexaneStream>>>;

lazy_static! {
    pub(crate) static ref CONFIGS: ConfigStore = Arc::new(Mutex::new(Vec::new()));
}


async fn parse_config(buffer: String) -> String {
	let config: HexaneStream = serde_json::from_str(buffer.as_str());

	// FIXME: this is not proper deserialization
    match from_slice::<HexaneStream>(&buffer) { 
        Ok(hexane) => {

            if let Ok(mut configs) = CONFIGS.lock() {
                configs.push(hexane);
                return "[INF] parse_config: config push success".to_string();
            }
            else {
                return "[ERR] parse_config: error on config lock".to_string();
            }
        }
        Err(e)=> {
            return "[ERR] parse_config: parser error. not a HexaneStream type (??)".to_string();
        }
    }
}
