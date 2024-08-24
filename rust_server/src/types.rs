use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::sync::mpsc::Sender;
use actix_web::{web, App, HttpServer, Responder};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;

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

#[derive(Debug, Clone)]
struct Message {
    msg_type:   String,
    msg:        String,
}

#[derive(Debug, Clone)]
struct TypedConfig {
    config_type:    String,
    config:         Box<dyn std::any::Any + Send + Sync>,
}

#[derive(Debug, Clone)]
struct Stream {
    buffer:     Vec<u8>,
    length:     usize,
}

#[derive(Debug, Clone)]
struct TableMap {
    headers:    Vec<String>,
    values:     Vec<Vec<String>>,
}

#[derive(Debug, Clone)]
struct Threadless {
    target_proc:    String,
    target_module:  String,
    target_func:    String,
    loader_asm:     String,
    execute:        String,
}

#[derive(Debug, Clone)]
struct Sources {
    sources:                Vec<String>,
    include_directories:    Vec<String>,
    dependencies:           Vec<String>,
    pre_build_dependencies: Vec<String>,
}

#[derive(Debug, Clone)]
struct Loader {
    root_directory: String,
    linker_script:  String,
    rsrc_script:    String,
    rsrc_binary:    String,
    sources:        Vec<String>,
    injection:      Option<TypedConfig>,
}

#[derive(Debug, Clone)]
struct Module {
    build_type:     i32,
    output_name:    String,
    root_directory: String,
    linker_script:  String,
    files:          Option<Sources>,
    loader:         Option<Loader>,
    components:     Vec<String>,
    definitions:    HashMap<String, Vec<u8>>,
}

#[derive(Debug, Clone)]
struct Config {
    arch:           String,
    debug:          bool,
    hostname:       String,
    working_hours:  String,
    sleeptime:      i32,
    jitter:         i32,
}

#[derive(Debug, Clone)]
struct Network {
    ingress_pipename:   String,
    ingress_peer:       u32,
    group_id:           i32,
    config:             Box<dyn std::any::Any + Send + Sync>,
}

#[derive(Debug, Clone)]
struct SmbConfig {
    egress_pipename:    String,
    egress_peer:        String,
}

#[derive(Debug, Clone)]
struct ProxyConfig {
    address:    String,
    port:       String,
    proto:      String,
    username:   String,
    password:   String,
}

#[derive(Debug, Clone)]
struct HttpConfig {
    address:    String,
    domain:     String,
    useragent:  String,
    port:       i32,
    endpoints:  Vec<String>,
    headers:    Vec<String>,
    proxy:      Option<ProxyConfig>,
    handle:     Option<App<None>>,
    sig_term:   Option<Sender<bool>>,
    ready:      Option<Sender<bool>>,
    group_id:   i32,
    next:       Option<Box<HttpConfig>>,
}

#[derive(Debug, Clone)]
struct JsonConfig {
    config:     Option<MainConfig>,
    network:    Option<TypedConfig>,
    builder:    Option<BuilderConfig>,
    loader:     Option<LoaderConfig>,
}

#[derive(Debug, Clone)]
struct MainConfig {
    arch:           String,
    debug:          bool,
    encrypt:        bool,
    hostname:       String,
    working_hours:  String,
    killdate:       String,
    sleeptime:      i32,
    jitter:         i32,
}

#[derive(Debug, Clone)]
struct BuilderConfig {
    output_name:            String,
    root_directory:         String,
    linker_script:          String,
    dependencies:           Vec<String>,
    include_directories:    Vec<String>,
    loaded_modules:         Vec<String>,
}

#[derive(Debug, Clone)]
struct LoaderConfig {
    root_directory:     String,
    linker_script:      String,
    rsrc_script:        String,
    rsrc_binary:        String,
    sources:            Vec<String>,
    dependencies:       Vec<String>,
    injection:          Option<TypedConfig>,
}

#[derive(Debug, Clone)]
struct ImplantConfig {
    network_profile:    Box<dyn std::any::Any + Send + Sync>,
    profile_type_id:    u32,
    current_task_id:    u32,
    hostname:           String,
    working_hours:      i32,
    sleeptime:          u32,
    jitter:             u32,
    killdate:           i64,
    proxy_bool:         bool,
}

#[derive(Debug, Clone)]
struct CompilerConfig {
    debug:              bool,
    arch:               String,
    mingw:              String,
    linker:             String,
    objcopy:            String,
    assembler:          String,
    windres:            String,
    strip:              String,
    file_extension:     String,
    build_directory:    String,
    flags:              Vec<String>,
}

#[derive(Debug, Clone)]
struct WriteChannel {
    buffer:     Option<Vec<u8>>,
    table:      Option<Vec<Vec<String>>>,
    is_active:  bool,
}

#[derive(Debug, Clone)]
struct HexaneConfig {
    current_taskid:     u32,
    peer_id:            u32,
    group_id:           i32,
    build_type:         i32,
    mu:                 Arc<Mutex<()>>,
    db:                 Option<sqlx::database>,
    write_chan:         Option<WriteChannel>,
    command_chan:       Option<Sender<String>>,
    db_name:            String,
    key:                Vec<u8>,
    shellcode:          Vec<u8>,
    config_bytes:       Vec<u8>,
    active:             bool,
    user_config:        Option<JsonConfig>,
    implant_config:     Option<ImplantConfig>,
    compiler_config:    Option<CompilerConfig>,
    user_session:       Option<Session>,
    next:               Option<Box<HexaneConfig>>,
}

#[derive(Debug, Clone)]
struct Parser {
    peer_id:    u32,
    task_id:    u32,
    msg_type:   u32,
    msg_length: u32,
    msg_buffer: Vec<u8>,
    big_endian: bool,
}

#[derive(Debug, Clone)]
struct Payloads {
    head:   Option<Box<HexaneConfig>>,
    group:  i32,
}

#[derive(Debug, Clone)]
struct Servers {
    head:   Option<Box<HttpConfig>>,
    group:  i32,
}

#[derive(Debug, Clone)]
struct Session {
    username: String,
    is_admin: bool,
}

#[derive(Debug, Clone)]
struct Headers {
    key: String,
    val: String,
}