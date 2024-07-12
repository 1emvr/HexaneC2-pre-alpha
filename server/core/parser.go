package core

import (
	"bytes"
	"encoding/binary"
)

func CreateParser(buffer []byte) *Parser {
	var parser = new(Parser)

	parser.Buffer = buffer
	parser.BigEndian = true
	parser.Length = uint32(len(buffer))

	return parser
}

func (p *Parser) ParseByte() []byte {
	var buffer = make([]byte, 1)

	for i := range buffer {
		buffer[i] = 0
	}

	if p.Length >= 1 {

		copy(buffer, p.Buffer[:1])
		p.Length -= 1

		if p.Length == 0 {
			p.Buffer = []byte{}

		} else {
			p.Buffer = p.Buffer[1:]
		}
	}

	return buffer
}

func (p *Parser) ParseBool() bool {
	var integer = make([]byte, 4)

	for i := range integer {
		integer[i] = 0
	}

	if p.Length >= 4 {

		copy(integer, p.Buffer[:4])
		p.Length -= 4

		if p.Length == 0 {
			p.Buffer = []byte{}

		} else {
			p.Buffer = p.Buffer[4:]
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

	if p.Length >= 4 {

		copy(buffer, p.Buffer[:4])
		p.Length -= 4

		if p.Length == 0 {
			p.Buffer = []byte{}

		} else {
			p.Buffer = p.Buffer[4:]
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

	if p.Length >= 8 {

		copy(buffer, p.Buffer[:8])
		p.Length -= 8

		if p.Length == 0 {
			p.Buffer = []byte{}
		} else {
			p.Buffer = p.Buffer[8:]
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

	if p.Length >= 4 {
		size := p.ParseDword()

		if size != 0 {
			buffer = make([]byte, size)
			copy(buffer, p.Buffer[:size])

			p.Length -= size

			if p.Length == 0 {
				p.Buffer = []byte{}

			} else {
				p.Buffer = p.Buffer[size:]
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
