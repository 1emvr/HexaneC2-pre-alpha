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

func (h *HexaneConfig) DispatchCommand() (*Stream, error) {
	var (
		err    error
		cmd    []byte
		stream *Stream
	)

	if stream = h.CreateStreamWithHeaders(TypeTasking); stream == nil {
		return nil, fmt.Errorf("stream returned nil")
	}

	if h.CommandChan == nil {
		return nil, fmt.Errorf("command channel is nil")
	}

	select {
	case blob := <-h.CommandChan:

		WrapMessage("DBG", fmt.Sprintf("%d : %s", h.PeerId, blob))
		if cmd, err = h.ProcessCommand(blob); err != nil {
			return nil, err
		}

		h.CurrentTaskId++
		stream.PackBytes(cmd)

		return stream, nil

	default:

		WrapMessage("DBG", fmt.Sprintf("%d : CommandNoJob", h.PeerId))
		stream.PackDword(CommandNoJob)

		return stream, nil
	}
}

func (h *HexaneConfig) ProcessParser(parser *Parser) ([]byte, error) {
	var (
		stream *Stream
		err    error
	)

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

		WrapMessage("DBG", fmt.Sprintf("response from: %d", parser.PeerId))

		h.WriteChan.ParseTable(parser)
		if stream, err = h.DispatchCommand(); err != nil {
			return nil, err
		}

	case TypeTasking:

		WrapMessage("DBG", fmt.Sprintf("task request from: %d", parser.PeerId))
		if stream, err = h.DispatchCommand(); err != nil {
			return nil, err
		}

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
