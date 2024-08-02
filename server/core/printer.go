package core

import (
	"bytes"
	"fmt"
	"github.com/olekukonko/tablewriter"
	"strconv"
)

func (w *WriteChannel) ParseTable(parser *Parser) {
	var (
		heads []string
		rows  [][]string
	)

	switch parser.MsgType {
	case TypeCheckin:
		{
			heads = []string{"PeerId", "Hostname", "Domain", "Username", "Interfaces"}
			row := []string{strconv.Itoa(int(parser.PeerId)), parser.ParseString(), parser.ParseString(), parser.ParseString(), parser.ParseString()}
			rows = append(rows, row)
		}

	case TypeTasking:
		{
			switch parser.ParseDword() {
			case CommandDir:
				{
					heads = []string{"Mode", "Length", "LastWriteTime", "Name"}
					row := make([]string, 4)

					for parser.MsgLength != 0 {
						IsDir := parser.ParseDword()

						if IsDir != 0 {
							row[0], row[1] = "dir", "n/a"
						} else {
							size := parser.ParseDword64()
							row[0], row[1] = "", FormatSize(size)
						}

						row[2] = fmt.Sprintf("%d/%d/%d %d:%d:%d", parser.ParseDword(), parser.ParseDword(), parser.ParseDword(), parser.ParseDword(), parser.ParseDword(), parser.ParseDword())
						row[3] = parser.ParseString()

						rows = append(rows, row)
					}
				}
			case CommandMods:
				{
					heads = []string{"ModName", "BaseAddress"}
					row := make([]string, 2)

					for parser.MsgLength != 0 {
						row[0], row[1] = parser.ParseString(), fmt.Sprintf("0x%X", parser.ParseDword64())
						rows = append(rows, row)
					}
				}
			}
		}
	}

	w.PrintTable(heads, rows)
}

func (w *WriteChannel) AttachBuffer() {
	w.IsActive = true
	w.Buffer.Reset()
}

func (w *WriteChannel) DetachBuffer() {
	w.IsActive = false
}

func CreateOutputChannel() *WriteChannel {
	buffer := new(bytes.Buffer)
	table := tablewriter.NewWriter(buffer)

	return &WriteChannel{
		Buffer: buffer,
		Table:  table,
	}
}

func (w *WriteChannel) PrintTable(heads []string, rows [][]string) {
	if !w.IsActive {
		return
	}

	w.Table.SetCenterSeparator("-")
	w.Table.SetBorder(false)
	w.Table.SetHeader(heads)

	for _, row := range rows {
		w.Table.Append(row)
	}

	fmt.Println()
	w.Table.Render()
	fmt.Println(w.Buffer.String())
	fmt.Println()

	w.Buffer.Reset()
}
