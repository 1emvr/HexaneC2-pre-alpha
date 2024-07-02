package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/fatih/color"
	"github.com/rodaine/table"
	"strconv"
)

const (
	CommandDir        uint32 = 0x7FFFFFFF
	CommandMods       uint32 = 0x7FFFFFFE
	CommandNoJob      uint32 = 0x7FFFFFFD
	CommandShutdown   uint32 = 0x7FFFFFFC
	CommandUpdatePeer uint32 = 0x7FFFFFFB
)

var CommandMap = map[string]uint32{
	"dir":      CommandDir,
	"mods":     CommandMods,
	"shutdown": CommandShutdown,
}

type TableHeaders struct {
	Headers []string
	Values  []string
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

func CreateParser(buffer []byte) *Message {
	var parser = new(Message)

	parser.Buffer = buffer
	parser.BigEndian = false
	parser.Length = uint32(len(buffer))

	return parser
}

func (m *Message) ParseByte() []byte {
	var buffer = make([]byte, 1)

	for i := range buffer {
		buffer[i] = 0
	}

	if m.Length >= 1 {
		if m.Length == 1 {
			copy(buffer, m.Buffer[:m.Length])
			m.Buffer = []byte{}
		} else {
			copy(buffer, m.Buffer[:m.Length-1])
			m.Buffer = m.Buffer[1:]
		}
	}
	WrapMessage("DBG", fmt.Sprintf("parsing byte: %s", string(buffer)))
	return buffer
}

func (m *Message) ParseBool() bool {
	var integer = make([]byte, 4)

	for i := range integer {
		integer[i] = 0
	}

	if m.Length >= 4 {
		if m.Length == 4 {
			copy(integer, m.Buffer[:m.Length])
			m.Buffer = []byte{}
		} else {
			copy(integer, m.Buffer[:m.Length-4])
			m.Buffer = m.Buffer[4:]
		}
	}

	if m.BigEndian {
		return int(binary.BigEndian.Uint32(integer)) != 0
	} else {
		return int(binary.LittleEndian.Uint32(integer)) != 0
	}
}

func (m *Message) ParseDword() uint32 {
	var buffer = make([]byte, 4)

	for i := range buffer {
		buffer[i] = 0
	}

	if m.Length >= 4 {
		if m.Length == 4 {
			copy(buffer, m.Buffer[:m.Length])
			m.Buffer = []byte{}
		} else {
			copy(buffer, m.Buffer[:m.Length-4])
			m.Buffer = m.Buffer[4:]
		}
	}

	if m.BigEndian {
		WrapMessage("DBG", fmt.Sprintf("parsing uint32 big endian: %d", binary.BigEndian.Uint32(buffer)))
		return binary.BigEndian.Uint32(buffer)
	} else {
		WrapMessage("DBG", fmt.Sprintf("parsing uint32 little endian: %d", binary.LittleEndian.Uint32(buffer)))
		return binary.LittleEndian.Uint32(buffer)
	}
}

func (m *Message) ParseDword64() uint64 {
	var buffer = make([]byte, 8)

	for i := range buffer {
		buffer[i] = 0
	}

	if m.Length >= 8 {
		if m.Length == 8 {
			copy(buffer, m.Buffer[:m.Length])
			m.Buffer = []byte{}
		} else {
			copy(buffer, m.Buffer[:m.Length-8])
			m.Buffer = m.Buffer[8:]
		}
	}

	if m.BigEndian {
		WrapMessage("DBG", fmt.Sprintf("ParseDword64: %d\n", binary.LittleEndian.Uint64(buffer)))
		return binary.LittleEndian.Uint64(buffer)
	} else {
		WrapMessage("DBG", fmt.Sprintf("ParseDword64: %d\n", binary.BigEndian.Uint64(buffer)))
		return binary.BigEndian.Uint64(buffer)
	}
}

func (m *Message) ParseBytes() []byte {
	var buffer []byte

	if m.Length >= 4 {
		size := m.ParseDword()

		if m.Length != 0 {
			if size == m.Length {
				buffer, m.Buffer = m.Buffer[:m.Length], m.Buffer[m.Length:]
			} else {
				buffer, m.Buffer = m.Buffer[:size], m.Buffer[size:]
			}
		}
	}

	WrapMessage("DBG", fmt.Sprintf("ParseBytes: buffer: %s\n", string(buffer)))
	return buffer
}

func (m *Message) ParseWString() string {
	return string(bytes.Trim([]byte(DecodeUTF16(m.ParseBytes())), "\x00"))
}
func (m *Message) ParseString() string { return string(m.ParseBytes()) }

func (m *Message) ParserPrintData(CmdId uint32) bool {
	var (
		tMap TableHeaders
		ok   bool
	)

	if CmdId == TypeCheckin {
		if tMap, ok = TableMap[TypeCheckin]; ok {
			tMap.Values[0] = m.ParseString()
			tMap.Values[1] = m.ParseString()
			tMap.Values[2] = m.ParseString()
			tMap.Values[3] = m.ParseString()
		}
	}
	if CmdId == CommandDir {
		if tMap, ok = TableMap[CommandDir]; ok {
			IsDir := strconv.FormatBool(m.ParseBool())

			if IsDir == "true" {
				tMap.Values[0] = "dir"
				tMap.Values[1] = "n/a"
			} else {
				tMap.Values[0] = ""
				tMap.Values[1] = strconv.Itoa(int(m.ParseDword64()))
			}

			Day := m.ParseDword()
			Month := m.ParseDword()
			Year := m.ParseDword()
			tMap.Values[2] = fmt.Sprintf("%02d/%02d/%d", Day, Month, Year)

			Hour := m.ParseDword()
			Minute := m.ParseDword()
			Second := m.ParseDword()
			tMap.Values[3] = fmt.Sprintf("%02d:%02d:%d", Hour, Minute, Second)
			tMap.Values[4] = m.ParseString()
		}
	}
	if CmdId == CommandMods {
		if tMap, ok = TableMap[CommandMods]; ok {
			tMap.Values[0] = m.ParseString()
			tMap.Values[1] = fmt.Sprintf("0x%X", m.ParseDword64())
		}
	}
	return m.ParseTable(tMap)
}

func (m *Message) ParseTable(tmap TableHeaders) bool {

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
