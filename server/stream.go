package main

import (
	"bytes"
	"encoding/binary"
	"golang.org/x/text/encoding/unicode"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

func EncodeUTF8(s string) []byte {

	if !strings.HasSuffix(s, "\x00") {
		s += "\x00"
	}
	return []byte(s)
}

func EncodeUTF16(s string) []byte {
	var (
		err     error
		encoded string
	)

	if !strings.HasSuffix(s, "\x00\x00") {
		s += "\x00\x00"
	}

	uni := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)

	if encoded, err = uni.NewEncoder().String(s); err != nil {
		WrapMessage("ERR", "failed to convert UTF16: "+s)
		encoded = ""
	}

	return []byte(encoded)
}

func DecodeUTF16(b []byte) string {
	var (
		u16 = make([]uint16, 1)
		u8  = make([]byte, 4)
	)

	ret := &bytes.Buffer{}
	length := len(b)

	for i := 0; i < length; i += 2 {
		u16[0] = uint16(b[i]) + (uint16(b[i+1]) << 8)
		runes := utf16.Decode(u16)
		written := utf8.EncodeRune(u8, runes[0])

		ret.Write(u8[:written])
	}

	return ret.String()
}

func CreateStream() *Stream {
	var stream = new(Stream)
	return stream
}

func (s *Stream) AddDword64(data int64) {
	var buffer = make([]byte, 8)

	binary.LittleEndian.PutUint64(buffer, uint64(data))

	s.Buffer = append(s.Buffer, buffer...)
	s.Length += 8
}

func (s *Stream) AddDword(data uint32) {
	var buffer = make([]byte, 4)

	binary.LittleEndian.PutUint32(buffer, data)

	s.Buffer = append(s.Buffer, buffer...)
	s.Length += 4
}

func (s *Stream) AddInt32(data int32) {
	var buffer = make([]byte, 4)

	binary.LittleEndian.PutUint32(buffer, uint32(data))

	s.Buffer = append(s.Buffer, buffer...)
	s.Length += 4
}

func (s *Stream) AddBytes(data []byte) {
	var buffer = make([]byte, 4)

	binary.LittleEndian.PutUint32(buffer, uint32(len(data)))

	s.Buffer = append(s.Buffer, buffer...)
	s.Buffer = append(s.Buffer, data...)

	s.Length += 4
	s.Length += len(data)
}

func (s *Stream) AddString(data string) {
	s.AddBytes(EncodeUTF8(data))
}

func (s *Stream) AddWString(data string) {
	s.AddBytes(EncodeUTF16(data))
}
