package core

import (
	"database/sql"
	"encoding/json"
	"os"
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
