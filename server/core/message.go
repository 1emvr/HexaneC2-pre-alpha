package core

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"math/bits"
	"os"
	"strings"
)

const HeaderLength = 12

var (
	CommandMap = map[string]uint32{
		"dir":      CommandDir,
		"mods":     CommandMods,
		"shutdown": CommandShutdown,
	}
)

func (h *HexaneConfig) SaveConfig() error {
	var (
		err  error
		file *os.File
	)

	if file, err = os.Create(h.Database + ".json"); err != nil {
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
		db  *sql.DB
	)

	h.Database = h.UserConfig.Builder.OutputName + ".db"
	if db, err = sql.Open("sqlite3", h.Database); err != nil {
		return nil, err
	}

	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS parsers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		data BLOB)`); err != nil {
		return nil, err
	}

	return db, nil
}

func (h *HexaneConfig) ResponseWorker() error {
	var (
		err  error
		data []byte
	)

	if h.db, err = h.SqliteInit(); err != nil {
		return err
	}
	defer func() {
		if err = h.db.Close(); err != nil {
			WrapMessage("ERR", "error closing database: "+err.Error())
		}
	}()

	for parser := range h.ResponseChan {
		if data, err = json.Marshal(parser); err != nil {
			return fmt.Errorf("marshal response to JSON: " + err.Error())
		}

		if _, err = h.db.Exec(`INSERT INTO parsers (data) VALUES (?)`, string(data)); err != nil {
			return fmt.Errorf("write response to JSON: " + err.Error())
		}
	}

	return nil
}

func (h *HexaneConfig) ProcessParsers() error {
	var (
		err  error
		rows *sql.Rows
	)

	if rows, err = h.db.Query(`SELECT data FROM parsers`); err != nil {
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

func ParseMessage(body []byte) ([]byte, error) {
	var (
		err    error
		offset uint32
		parser *Parser
		config *HexaneConfig
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

		if config = GetConfigByPeerId(parser.PeerId); config != nil {
			// todo
		} else {
			WrapMessage("ERR", "could not find peer in the database")
			stream.Buffer = []byte("200 ok")
		}

		body = body[offset:]
	}

	return stream.Buffer, err
}
