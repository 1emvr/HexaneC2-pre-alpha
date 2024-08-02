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

func (h *HexaneConfig) DispatchCommand() ([]byte, error) {
	var (
		err error
		cmd []byte
	)

	stream := new(Stream)

	if h.CommandChan != nil {
		for blob := range h.CommandChan {
			if cmd, err = ProcessCommand(blob); err != nil {
				WrapMessage("ERR", err.Error())
			}
			stream.PackBytes(cmd)
		}
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
