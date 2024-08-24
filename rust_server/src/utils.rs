mod utils {
    use std::fs::{self, File};
    use std::io::{self, Write};
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::mpsc::Receiver;
    use std::time::{SystemTime, UNIX_EPOCH};

    use rand::Rng;
    use regex::Regex;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::fmt;

    fn print_channel(rx: Receiver<Message>, exit_rx: Receiver<bool>) {
        loop {
            select! {
            recv(exit_rx) -> exit => {
                if exit.unwrap_or(false) {
                    return;
                }
            },
            recv(rx) -> msg => {
                let msg = msg.unwrap();
                if !DEBUG && msg.msg_type == "DBG" {
                    continue;
                }
                println!("[{}] {}", msg.msg_type, msg.msg);
            }
        }
        }
    }

    fn egg_hunt_double_d(data: &[u8], egg: &[u8]) -> Result<usize, String> {
        let egg_len = egg.len();
        let data_len = data.len();

        for i in 0..=data_len - egg_len {
            if match_bytes(&data[i..i + egg_len], egg) {
                if i + 4 + egg_len > data_len {
                    return Err("out-of-bounds read in egg hunting".to_string());
                }
                if match_bytes(&data[i + 4..i + 4 + egg_len], egg) {
                    return Ok(i);
                }
            }
        }
        Err("egg was not found".to_string())
    }

    fn generate_uuid(n: usize) -> String {
        const CHARACTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let mut rng = rand::thread_rng();
        let mut buffer = vec![0; n];

        for i in 0..n {
            buffer[i] = CHARACTERS[rng.gen_range(0..CHARACTERS.len())];
        }

        String::from_utf8(buffer).unwrap()
    }

    fn create_path(path: &str, mode_perm: u32) -> io::Result<()> {
        if !Path::new(path).exists() {
            fs::create_dir(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(mode_perm))?;
        }
        Ok(())
    }

    fn write_file(name: &str, data: &[u8]) -> io::Result<()> {
        let mut file = File::create(name)?;
        file.write_all(data)?;
        Ok(())
    }

    fn find_files(path: &str) -> io::Result<Vec<PathBuf>> {
        fs::read_dir(path)?
            .map(|res| res.map(|e| e.path()))
            .collect::<Result<Vec<_>, io::Error>>()
    }

    fn search_file(root_path: &str, file_name: &str) -> io::Result<()> {
        let files = find_files(root_path)?;

        for file in files {
            if file.file_name() == file_name.into() {
                return Ok(());
            }
        }

        Err(io::Error::new(io::ErrorKind::NotFound, "File not found"))
    }

    fn move_file(src_path: &str, dst_path: &str) -> io::Result<()> {
        let file_name = Path::new(src_path).file_name().unwrap().to_str().unwrap();
        let dst_file = Path::new(dst_path).join(file_name);

        fs::create_dir_all(dst_path)?;
        fs::rename(src_path, dst_file)?;
        Ok(())
    }

    fn create_temp(tmp_path: &str) -> io::Result<()> {
        if !Path::new(tmp_path).exists() {
            fs::create_dir_all(tmp_path)?;
        }
        Ok(())
    }

    fn get_cwd() -> String {
        match std::env::current_exe() {
            Ok(exe_path) => exe_path.parent().unwrap().to_str().unwrap().to_string(),
            Err(err) => {
                wrap_message("ERR", &format!("Error getting cwd: {:?}", err));
                String::new()
            }
        }
    }

    fn clear() {
        let mut command = Command::new("clear");
        command.status().unwrap();
    }

    fn read_json<T: Deserialize<'static>>(cfg_path: &str) -> Result<T, io::Error> {
        let buffer = fs::read_to_string(cfg_path)?;
        let config: T = serde_json::from_str(&buffer)?;
        Ok(config)
    }

    fn merge_maps<K: std::hash::Hash + Eq + Clone, V: Clone>(
        m1: &HashMap<K, V>,
        m2: &HashMap<K, V>,
    ) -> HashMap<K, V> {
        m1.iter().chain(m2).map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    fn map_to_struct<M: Serialize, T: for<'de> Deserialize<'de>>(map: M) -> Result<T, serde_json::Error> {
        let data = serde_json::to_vec(&map)?;
        let result = serde_json::from_slice(&data)?;
        Ok(result)
    }

    fn create_cpp_array(buffer: &[u8], length: usize) -> String {
        let mut array = String::from("{");

        for (i, &byte) in buffer.iter().enumerate() {
            if i == length - 1 {
                array.push_str(&format!("0x{:02X}", byte));
            } else {
                array.push_str(&format!("0x{:02X},", byte));
            }
        }
        array.push('}');
        array
    }

    fn parse_working_hours(working_hours: &str) -> Result<i32, String> {
        if working_hours.is_empty() {
            return Ok(0);
        }

        let re = Regex::new(r"^[12]?[0-9]:[0-6][0-9]-[12]?[0-9]:[0-6][0-9]$")
            .map_err(|_| "failed to parse working hours: invalid format")?;

        if !re.is_match(working_hours) {
            return Err("failed to parse working hours: invalid format. Usage: 8:00-17:00".to_string());
        }

        let start_and_end: Vec<&str> = working_hours.split('-').collect();
        let start: Vec<&str> = start_and_end[0].split(':').collect();
        let end: Vec<&str> = start_and_end[1].split(':').collect();

        let start_hour: i32 = start[0].parse().unwrap();
        let start_minute: i32 = start[1].parse().unwrap();
        let end_hour: i32 = end[0].parse().unwrap();
        let end_minute: i32 = end[1].parse().unwrap();

        if start_hour < 0 || start_hour > 24 || end_hour < 0 || end_hour > 24 || start_minute < 0 || start_minute > 60 {
            return Err("failed to parse working hours: invalid hour or minutes".to_string());
        }
        if end_hour < start_hour || (start_hour == end_hour && end_minute <= start_minute) {
            return Err("failed to parse working hours: overlapping start and end times. End cannot be sooner than start".to_string());
        }

        let mut int_working_hours: i32 = 1 << 22;
        int_working_hours |= (start_hour & 0b011111) << 17;
        int_working_hours |= (start_minute & 0b111111) << 11;
        int_working_hours |= (end_hour & 0b011111) << 6;
        int_working_hours |= (end_minute & 0b111111);

        Ok(int_working_hours)
    }

    fn dbg_print_bytes(tag: &str, buffer: &[u8]) -> String {
        let mut output = String::from(tag);

        for byte in buffer {
            output.push_str(&format!("{:x} ", byte));
        }

        output.push('\n');
        output
    }

    fn format_size(size: u64) -> String {
        const KB: u64 = 1 << 10;
        const MB: u64 = 1 << 20;
        const GB: u64 = 1 << 30;

        match size {
            size if size >= GB => format!("{:.2} GB", size as f64 / GB as f64),
            size if size >= MB => format!("{:.2} MB", size as f64 / MB as f64),
            size if size >= KB => format!("{:.2} KB", size as f64 / KB as f64),
            _ => "null".to_string(),
        }
    }

    fn wrap_message(typ: &str, msg: &str) {
        CB.lock().unwrap().send(Message { msg_type: typ.to_string(), msg: msg.to_string() }).unwrap();
    }

    fn dquote(s: &str) -> String {
        format!("\"{}\"", s)
    }

    fn squote(s: &str) -> String {
        format!("'{}'", s)
    }

    fn tick(s: &str) -> String {
        format!("`{}`", s)
    }

    fn generate_peer_id() -> u32 {
        bits::reverse32(rand::thread_rng().gen())
    }

    #[derive(Serialize, Deserialize)]
    struct HexaneConfig {
        user_config: HashMap<String, String>,
    }

    impl HexaneConfig {
        fn read_json(cfg_path: &str) -> Result<Self, io::Error> {
            let buffer = fs::read_to_string(cfg_path)?;
            let config: HexaneConfig = serde_json::from_str(&buffer)?;
            if SHOW_CONFIGS {
                println!("Unmarshalled data:");
                println!("{}", serde_json::to_string_pretty(&config.user_config)?);
            }
            Ok(config)
        }
    }

    #[derive(Debug)]
    struct Message {
        msg_type: String,
        msg: String,
    }

    lazy_static! {
    static ref DEBUG: bool = std::env::var("DEBUG").unwrap_or("false".to_string()) == "true";
    static ref SHOW_CONFIGS: bool = std::env::var("SHOW_CONFIGS").unwrap_or("false".to_string()) == "true";
    static ref CB_CHANNEL: std::sync::Mutex<std::sync::mpsc::Sender<Message>> = std::sync::Mutex::new(std::sync::mpsc::channel().0);
}
}