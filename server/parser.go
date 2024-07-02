package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/fatih/color"
	"github.com/rodaine/table"
	"strconv"
)

var CommandMap = map[string]uint32{
	"dir":      CommandDir,
	"mods":     CommandMods,
	"shutdown": CommandShutdown,
}

var TableMap = map[uint32]TableHeaders{
	TypeCheckin: {
		Headers: []string{"pid", "host", "domain", "username", "ipconfig"},
		Values:  make([]string, 5),
	},
	CommandDir: {
		Headers: []string{"directory", "size", "creation date", "creation time", "name"},
		Values:  make([]string, 5),
	},
	CommandMods: {
		Headers: []string{"module", "base address"},
		Values:  make([]string, 2),
	},
}

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

func (p *Parser) ParserPrintData(TypeId uint32) bool {
	var (
		tMap TableHeaders
		ok   bool
	)

	if TypeId == TypeCheckin {
		if tMap, ok = TableMap[TypeCheckin]; ok {

			WrapMessage("INF", "======== CHECKIN ========")

			tMap.Values[0] = strconv.Itoa(int(p.PeerId))
			tMap.Values[1] = p.ParseString()
			tMap.Values[2] = p.ParseString()
			tMap.Values[3] = p.ParseString()
			tMap.Values[4] = p.ParseString()
		}
	}

	if TypeId == TypeTasking {

		CmdId := p.ParseDword()
		if CmdId == CommandDir {
			if tMap, ok = TableMap[CommandDir]; ok {

				WrapMessage("INF", "======== DIRECTORY ========")

				IsDir := strconv.FormatBool(p.ParseBool())
				if IsDir == "true" {
					tMap.Values[0] = "dir"
					tMap.Values[1] = "n/a"
				} else {
					tMap.Values[0] = ""
					tMap.Values[1] = strconv.Itoa(int(p.ParseDword64()))
				}

				Day := p.ParseDword()
				Month := p.ParseDword()
				Year := p.ParseDword()
				tMap.Values[2] = fmt.Sprintf("%02d/%02d/%d", Day, Month, Year)

				Hour := p.ParseDword()
				Minute := p.ParseDword()
				Second := p.ParseDword()
				tMap.Values[3] = fmt.Sprintf("%02d:%02d:%d", Hour, Minute, Second)
				tMap.Values[4] = p.ParseString()
			}
		}

		if CmdId == CommandMods {
			if tMap, ok = TableMap[CommandMods]; ok {

				WrapMessage("INF", "======== MODULES ========")

				tMap.Values[0] = p.ParseString()
				tMap.Values[1] = fmt.Sprintf("0x%X", p.ParseDword64())
			}
		}
	}

	return ParseTable(tMap)
}

func ParseTable(tmap TableHeaders) bool {

	hdrs := tmap.Headers
	vals := tmap.Values

	for k, v := range vals {
		if v == "" {
			vals[k] = "null"
		}
	}

	headersInterface := make([]interface{}, len(hdrs))
	for i, header := range hdrs {
		headersInterface[i] = header
	}

	valuesInterface := make([]interface{}, len(vals))
	for i, val := range vals {
		valuesInterface[i] = val
	}

	tbl := table.New(headersInterface...)
	format := color.New(color.FgCyan).SprintfFunc()

	tbl.WithHeaderFormatter(format)
	tbl.AddRow(valuesInterface...)

	fmt.Println()
	tbl.Print()
	fmt.Println()

	return true
}
