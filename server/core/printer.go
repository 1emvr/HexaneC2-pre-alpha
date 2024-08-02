package core

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/rodaine/table"
	"strconv"
)

var HeaderMap = map[uint32]TableMap{
	TypeCheckin: {
		Headers: []string{"PeerId", "Hostname", "Domain", "Username", "Interfaces"},
	},
	CommandDir: {
		Headers: []string{"Mode", "Length", "LastWriteTime", "Name"},
	},
	CommandMods: {
		Headers: []string{"ModName", "BaseAddress"},
	},
}

func (p *Parser) ParseTable() TableMap {
	var (
		heads, vals []string
	)

	switch p.MsgType {
	case TypeCheckin:
		{
			heads = []string{"PeerId", "Hostname", "Domain", "Username", "Interfaces"}
			vals = []string{strconv.Itoa(int(p.PeerId)), p.ParseString(), p.ParseString(), p.ParseString(), p.ParseString()}
		}

	case TypeTasking:
		{
			switch p.ParseDword() {
			case CommandDir:
				{
					heads = []string{"Mode", "Length", "LastWriteTime", "Name"}
					vals = make([]string, 0)

					for p.MsgLength != 0 {
						row := make([]string, 4)
						IsDir := p.ParseDword()

						if IsDir != 0 {
							row[0], row[1] = "dir", "n/a"

						} else {
							size := p.ParseDword64()
							row[0], row[1] = "", FormatSize(size)
						}

						row[2] = fmt.Sprintf("%d/%d/%d %d:%d:%d", p.ParseDword(), p.ParseDword(), p.ParseDword(), p.ParseDword(), p.ParseDword(), p.ParseDword())
						row[3] = p.ParseString()

						vals = append(vals, row[1], row[2], row[3])
					}
				}
			case CommandMods:
				{
					if tMap, ok := HeaderMap[CommandMods]; ok {
						tMap.Values = make([][]string, 0)

						for p.MsgLength != 0 {
							row := []string{p.ParseString(), fmt.Sprintf("0x%X", p.ParseDword64())}
							tMap.Values = append(tMap.Values, row)
						}

					}
				}
			}
		}
	}

	PrintTable(heads, vals)
	return false
}

func PrintTable(heads, vals []string) {
	headersInterface := make([]interface{}, len(heads))

	for i, header := range heads {
		headersInterface[i] = header
	}

	tbl := table.New(headersInterface...)
	format := color.New(color.FgCyan).SprintfFunc()

	tbl.WithHeaderFormatter(format)

	for _, row := range vals {
		rowInterface := make([]interface{}, len(row))

		for i, val := range row {
			rowInterface[i] = val
		}

		tbl.AddRow(rowInterface...)
	}

	fmt.Println()
	tbl.Print()
}
