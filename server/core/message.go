package core

import (
	"fmt"
	"strconv"
)

const HeaderLength = 12

func ProcessBodyToParser(b []byte) (*Parser, uint32, error) {
	var offset uint32

	WrapMessage("DBG", "creating parser from http body")
	parser := CreateParser(b)

	if parser.MsgLength < HeaderLength {
		return nil, 0, fmt.Errorf("parser length is not long enough")
	}

	if parser.MsgLength >= HeaderLength+4 {
		offset = parser.ParseDword()
		offset += HeaderLength + 4
	} else {
		offset = HeaderLength
	}

	if offset > parser.MsgLength {
		return nil, 0, nil
	}

	return parser, offset, nil

}

func (h *HexaneConfig) ProcessParser(p *Parser) ([]byte, error) {
	switch p.MsgType {
	case TypeCheckin:

		h.CommandChan = make(chan string, 5) // implant is checked-in
		h.Active = true

		p.ParseTable()
		return []byte(strconv.Itoa(int(p.PeerId))), nil

	case TypeResponse:
		p.ParseTable()
		return h.DispatchCommand()

	case TypeTasking:
		return h.DispatchCommand()

	default:
		return nil, fmt.Errorf("unknown msg type: %v", p.MsgType)
	}
}

func ResponseWorker(b []byte) ([]byte, error) {
	var (
		err    error
		offset uint32
		parser *Parser
		config *HexaneConfig
		rsp    []byte
	)

	WrapMessage("DBG", DbgPrintBytes("http body: ", b))

	for len(b) > 0 {
		if parser, offset, err = ProcessBodyToParser(b); err != nil {
			return nil, fmt.Errorf("processing message b to parser: bad parser or message length: %s", err)
		}

		parser.PeerId = parser.ParseDword()
		parser.TaskId = parser.ParseDword()
		parser.MsgType = parser.ParseDword()
		parser.MsgLength = parser.ParseDword()

		offset += parser.MsgLength

		if config = GetConfigByPeerId(parser.PeerId); config != nil {
			if err = config.SqliteInsertParser(parser); err != nil {
				return []byte("200 ok"), err
			}

			if rsp, err = config.ProcessParser(parser); err != nil {
				return []byte("200 ok"), err
			}
		} else {
			WrapMessage("ERR", fmt.Sprintf("could not find peer in the database: %d", parser.PeerId))
			rsp = []byte("200 ok")
		}

		if offset != 0 {
			b = b[offset:]
		} else {
			b = nil
		}
	}

	return rsp, err
}
