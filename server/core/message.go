package core

import (
	"fmt"
)

const HeaderLength = 12

func ResponseWorker(body []byte) ([]byte, error) {
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
		if parser.MsgType != TypeTasking {
			parser.MsgLength += 4
		}

		body = body[HeaderLength+parser.MsgLength:]

		if config = GetConfigByPeerId(parser.PeerId); config != nil {
			if err = config.SqliteInsertParser(parser); err != nil {
				return []byte("200 ok"), fmt.Errorf("SqliteInsertParser: %v", err)
			}

			if rsp, err = config.ProcessParser(parser); err != nil {
				return []byte("200 ok"), fmt.Errorf("ProcessParser: %v", err)
			}
		} else {
			err = fmt.Errorf("could not find peer in the database: %d", parser.PeerId)
			rsp = []byte("200 ok")
		}
	}

	return rsp, err
}
