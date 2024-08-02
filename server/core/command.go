package core

import (
	"fmt"
	"strings"
)

var (
	CommandMap = map[string]uint32{
		"dir":      CommandDir,
		"mods":     CommandMods,
		"shutdown": CommandShutdown,
	}
)

func (h *HexaneConfig) DispatchCommand(stream *Stream) {
	var (
		err error
		cmd []byte
	)

	if h.CommandChan != nil {
		for blob := range h.CommandChan {
			if cmd, err = ProcessCommand(blob); err != nil {
				WrapMessage("ERR", err.Error())
			}
			stream.PackBytes(cmd)
		}
	}
}

func (h *HexaneConfig) ProcessParser(parser *Parser) ([]byte, error) {
	var stream *Stream

	switch parser.MsgType {
	case TypeCheckin:

		h.Active = true
		h.CommandChan = make(chan string, 5)

		if h.WriteChan == nil {
			if h.WriteChan = CreateOutputChannel(); h.WriteChan == nil {
				return nil, fmt.Errorf("config write channel return nil")
			}
		}

		h.WriteChan.ParseTable(parser)
		if stream = h.CreateStreamWithHeaders(TypeCheckin); stream == nil {
			return nil, fmt.Errorf("stream returned nil")
		}

	case TypeResponse:

		h.WriteChan.ParseTable(parser)
		if stream = h.CreateStreamWithHeaders(TypeTasking); stream == nil {
			return nil, fmt.Errorf("stream returned nil")
		}

		h.DispatchCommand(stream)

	case TypeTasking:

		if stream = h.CreateStreamWithHeaders(TypeTasking); stream == nil {
			return nil, fmt.Errorf("stream returned nil")
		}

		h.DispatchCommand(stream)

	default:
		return nil, fmt.Errorf("unknown msg type: %v", parser.MsgType)
	}

	return stream.Buffer, nil
}

func ProcessCommand(input string) ([]byte, error) {
	var (
		cmdType    uint32
		args       string
		argsBuffer []string
		stream     *Stream
	)

	stream = new(Stream)

	if input != "" {
		buffer := strings.Split(input, " ")
		cmd := buffer[0]

		argsBuffer = append(argsBuffer, buffer[1:]...)
		args = strings.Join(argsBuffer, " ")

		for k, v := range CommandMap {
			if strings.EqualFold(k, cmd) {
				cmdType = v
				break
			}
		}
		if cmdType == 0 {
			return nil, fmt.Errorf("unknown command: %s", input)
		}
	} else {
		cmdType = CommandNoJob
	}

	stream.PackDword(cmdType)
	stream.PackString(args)

	return stream.Buffer, nil
}
