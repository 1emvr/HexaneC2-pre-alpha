use byteorder::{LittleEndian, WriteBytesExt};
use encoding_rs::UTF_16LE;
use std::string::FromUtf16Error;

#[derive(Debug)]
pub struct Stream {
    pub buffer: Vec<u8>,
}

impl Stream {
    pub fn new() -> Self {
        Stream {
            buffer: Vec::new()
        }
    }

    pub fn pack_byte(&mut self, data: u8) {
        self.buffer.push(data);
    }

    pub fn pack_uint64(&mut self, data: i64) {
        self.buffer.write_i64::<LittleEndian>(data).unwrap();
    }

    pub fn pack_uint32(&mut self, data: u32) {
        self.buffer.write_u32::<LittleEndian>(data).unwrap();
    }

    pub fn pack_int32(&mut self, data: i32) {
        self.buffer.write_i32::<LittleEndian>(data).unwrap();
    }

    pub fn pack_bytes(&mut self, data: &[u8]) {
        let len = data.len() as u32;
        self.pack_uint32(len);
        self.buffer.extend_from_slice(data);
    }

    pub fn pack_string(&mut self, data: &str) {
        let encoded = encode_utf8(data);
        self.pack_bytes(&encoded);
    }

    pub fn pack_wstring(&mut self, data: &str) {
        let encoded = encode_utf16(data);
        self.pack_bytes(&encoded);
    }

    pub fn create_header(&mut self, peer_id: u32, msg_type: u32, task_id: u32) {
        self.pack_uint32(peer_id);
        self.pack_uint32(task_id);
        self.pack_uint32(msg_type);
    }

    pub fn get_buffer(&self) -> &[u8] {
        &self.buffer
    }
}

fn encode_utf8(s: &str) -> Vec<u8> {
    let mut string = s.to_owned();

    if !string.ends_with('\x00') {
        string.push('\x00');
    }

    string.into_bytes()
}

fn encode_utf16(s: &str) -> Vec<u8> {
    let (mut encoded, _, _) = UTF_16LE.encode(s);

    if !encoded.ends_with(&[0x00, 0x00]) {
        encoded.to_mut().extend_from_slice(&[0x00, 0x00]);
    }

    encoded.into_owned()
}

fn decode_utf16(bytes: &[u8]) -> Result<String, FromUtf16Error> {
    let mut utf16 = Vec::with_capacity(bytes.len() / 2);

    for chunk in bytes.chunks(2) {
        utf16.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }

    String::from_utf16(&utf16)
}
