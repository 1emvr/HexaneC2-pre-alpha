package core

import (
	"bytes"
	"encoding/binary"
)

func CreateParser(buffer []byte) *Parser {
	var parser = new(Parser)

	parser.MsgBuffer = buffer
	parser.BigEndian = true
	parser.MsgLength = uint32(len(buffer))

	parser.PeerId = parser.ParseDword()
	parser.TaskId = parser.ParseDword()
	parser.MsgType = parser.ParseDword()

	return parser
}

func (p *Parser) ParseByte() []byte {
	var buffer = make([]byte, 1)

	for i := range buffer {
		buffer[i] = 0
	}

	if p.MsgLength >= 1 {

		copy(buffer, p.MsgBuffer[:1])
		p.MsgLength -= 1

		if p.MsgLength == 0 {
			p.MsgBuffer = []byte{}

		} else {
			p.MsgBuffer = p.MsgBuffer[1:]
		}
	}

	return buffer
}

func (p *Parser) ParseBool() bool {
	var integer = make([]byte, 4)

	for i := range integer {
		integer[i] = 0
	}

	if p.MsgLength >= 4 {

		copy(integer, p.MsgBuffer[:4])
		p.MsgLength -= 4

		if p.MsgLength == 0 {
			p.MsgBuffer = []byte{}

		} else {
			p.MsgBuffer = p.MsgBuffer[4:]
		}
	}

	if p.BigEndian {
		return int(binary.BigEndian.Uint32(integer)) != 0

	} else {
		return int(binary.LittleEndian.Uint32(integer)) != 0
	}
}

func (p *Parser) ParseDword() uint32 {
	var buffer = make([]byte, 4)

	for i := range buffer {
		buffer[i] = 0
	}

	if p.MsgLength >= 4 {

		copy(buffer, p.MsgBuffer[:4])
		p.MsgLength -= 4

		if p.MsgLength == 0 {
			p.MsgBuffer = []byte{}

		} else {
			p.MsgBuffer = p.MsgBuffer[4:]
		}
	}

	if p.BigEndian {
		return binary.BigEndian.Uint32(buffer)

	} else {
		return binary.LittleEndian.Uint32(buffer)
	}
}

func (p *Parser) ParseDword64() uint64 {
	var buffer = make([]byte, 8)

	for i := range buffer {
		buffer[i] = 0
	}

	if p.MsgLength >= 8 {

		copy(buffer, p.MsgBuffer[:8])
		p.MsgLength -= 8

		if p.MsgLength == 0 {
			p.MsgBuffer = []byte{}
		} else {
			p.MsgBuffer = p.MsgBuffer[8:]
		}
	}

	if p.BigEndian {
		return binary.BigEndian.Uint64(buffer)

	} else {
		return binary.LittleEndian.Uint64(buffer)
	}
}

func (p *Parser) ParseBytes() []byte {
	var buffer []byte

	if p.MsgLength >= 4 {
		size := p.ParseDword()

		if size != 0 {
			buffer = make([]byte, size)
			copy(buffer, p.MsgBuffer[:size])

			p.MsgLength -= size

			if p.MsgLength == 0 {
				p.MsgBuffer = []byte{}

			} else {
				p.MsgBuffer = p.MsgBuffer[size:]
			}
		}
	}

	return buffer
}

func (p *Parser) ParseWString() string {
	return string(bytes.Trim([]byte(DecodeUTF16(p.ParseBytes())), "\x00"))
}

func (p *Parser) ParseString() string {
	return string(p.ParseBytes())
}
