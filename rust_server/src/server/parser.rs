use byteorder::{BigEndian, LittleEndian, ByteOrder};
use std::convert::TryInto;

pub struct Parser {
    msg_buffer: Vec<u8>,
    big_endian: bool,
    msg_length: u32,
    peer_id:    u32,
    task_id:    u32,
    msg_type:   u32,
}

impl Parser {
    pub fn create_parser(buffer: Vec<u8>) -> Parser {
        let mut parser = Parser {
            msg_buffer: buffer,
            big_endian: true,
            msg_length: 0,
            peer_id:    0,
            task_id:    0,
            msg_type:   0,
        };

        parser.msg_length   = parser.msg_buffer.len() as u32;
        parser.peer_id      = parser.parse_dword();
        parser.task_id      = parser.parse_dword();
        parser.msg_type     = parser.parse_dword();

        parser
    }

    pub fn parse_byte(&mut self) -> Vec<u8> {
        if self.msg_length >= 1 {
            let buffer = self.msg_buffer[..1].to_vec();

            self.msg_buffer = self.msg_buffer[1..].to_vec();
            self.msg_length -= 1;

            buffer
        } else {
            vec![0; 1]
        }
    }

    pub fn parse_bool(&mut self) -> bool {
        let integer = self.parse_dword();
        integer != 0
    }

    pub fn parse_dword(&mut self) -> u32 {
        if self.msg_length >= 4 {
            let buffer = &self.msg_buffer[..4];

            self.msg_buffer = self.msg_buffer[4..].to_vec();
            self.msg_length -= 4;

            if self.big_endian {
                BigEndian::read_u32(buffer)
            } else {
                LittleEndian::read_u32(buffer)
            }
        } else {
            0
        }
    }

    pub fn parse_dword64(&mut self) -> u64 {
        if self.msg_length >= 8 {
            let buffer = &self.msg_buffer[..8];

            self.msg_buffer = self.msg_buffer[8..].to_vec();
            self.msg_length -= 8;

            if self.big_endian {
                BigEndian::read_u64(buffer)
            } else {
                LittleEndian::read_u64(buffer)
            }
        } else {
            0
        }
    }

    pub fn parse_bytes(&mut self) -> Vec<u8> {
        let size = self.parse_dword() as usize;

        if size > 0 && self.msg_length as usize >= size {
            let buffer = self.msg_buffer[..size].to_vec();

            self.msg_buffer = self.msg_buffer[size..].to_vec();
            self.msg_length -= size as u32;

            buffer
        } else {
            vec![]
        }
    }

    pub fn parse_wstring(&mut self) -> String {
        let bytes = self.parse_bytes();
        let string = decode_utf16(&bytes);

        string.trim_end_matches('\x00').to_string()
    }

    pub fn parse_string(&mut self) -> String {
        String::from_utf8(self.parse_bytes()).unwrap_or_default()
    }
}

fn decode_utf16(bytes: &[u8]) -> String {
    let mut u16_vec = Vec::with_capacity(bytes.len() / 2);

    for chunk in bytes.chunks(2) {
        let arr: [u8; 2] = chunk.try_into().unwrap_or([0, 0]);
        u16_vec.push(u16::from_le_bytes(arr));
    }
    String::from_utf16_lossy(&u16_vec)
}
