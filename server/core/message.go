package core

import (
	"fmt"
)

const HeaderLength = 16

func ResponseWorker(body []byte) ([]byte, error) {
	var (
		err    error
		config *HexaneConfig
		parser *Parser
		rsp    []byte
	)

	WrapMessage("DBG", DbgPrintBytes("http body: ", body))

	for len(body) > 0 {
		if parser = CreateParser(body); parser == nil {
			return nil, fmt.Errorf("parser returned nil")
		}

		if parser.MsgLength < HeaderLength {
			return nil, fmt.Errorf("parser length is not long enough")
		}

		body = body[HeaderLength+parser.MsgLength:]

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
	}

	WrapMessage("DBG", DbgPrintBytes("outgoing response: ", rsp))
	return rsp, err
}
