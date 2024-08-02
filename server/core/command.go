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
		buffer     []string
		argsBuffer []string
		args       string
		cmd        string
		cmdType    uint32
		stream     *Stream
	)

	stream = new(Stream)
	if UserInput != "" {
		buffer = strings.Split(UserInput, " ")
		cmd = buffer[0]

		argsBuffer = append(argsBuffer, buffer[1:]...)
		args = strings.Join(argsBuffer, " ")

		for k, v := range CommandMap {
			if strings.EqualFold(k, cmd) {
				cmdType = v
				break
			}
		}
		if cmdType == 0 {
			return nil, fmt.Errorf("unknown command: %s", UserInput)
		}
	} else {
		cmdType = CommandNoJob
	}

	stream.PackDword(cmdType)
	stream.PackString(args)
	return stream.Buffer, nil
}
