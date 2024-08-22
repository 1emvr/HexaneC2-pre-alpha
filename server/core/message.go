package core

import (
	"fmt"
)

const HeaderLength = 12

func ParseMessage(body []byte) ([]byte, error) {
	var (
		err    error
		config *HexaneConfig
		parser *Parser
		rsp    []byte
	)

	for len(body) > 0 {
		if parser = CreateParser(body); parser == nil {
			return nil, fmt.Errorf("parser returned nil")
		}

		if parser.MsgLength < HeaderLength && parser.MsgType != TypeTasking {
			return nil, fmt.Errorf("msg length too small: %d", parser.MsgLength)
		}

		body = body[HeaderLength+parser.MsgLength:]

		if config = GetConfigByPeerId(parser.PeerId); config != nil {
			if err = config.SqliteInsertParser(parser); err != nil {
				return []byte("200 ok"), fmt.Errorf("SqliteInsertParser: %v", err)
			}

			if rsp, err = config.ProcessTask(parser); err != nil {
				return []byte("200 ok"), fmt.Errorf("ProcessParser: %v", err)
			}
		} else {
			return []byte("200 ok"), fmt.Errorf("could not find peer in the database: %d", parser.PeerId)
		}
	}

	return rsp, err
}
