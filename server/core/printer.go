package core

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/rodaine/table"
	"strconv"
	"strings"
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

// response channel is parsed data *tablewriter.NewWriter(&channel)
func (p *Parser) ParseTable(TypeId uint32) TableMap {

	switch TypeId {
	case TypeCheckin:
		{
			if tMap, ok := HeaderMap[TypeCheckin]; ok {
				tMap.Values = [][]string{
					{strconv.Itoa(int(p.PeerId)), p.ParseString(), p.ParseString(), p.ParseString(), p.ParseString()},
				}
				return tMap
			}
		}

	case TypeTasking:
		{
			CmdId := p.ParseDword()

			switch CmdId {
			case CommandDir:
				{
					if tMap, ok := HeaderMap[CommandDir]; ok {
						tMap.Values = make([][]string, 0)

						for p.Length != 0 {
							row := make([]string, 4)
							IsDir := p.ParseDword()

							if IsDir != 0 {
								row[0], row[1] = "dir", "n/a"

							} else {
								size := p.ParseDword64()
								row[0], row[1] = "", FormatSize(size)
							}

							Month := p.ParseDword()
							Day := p.ParseDword()
							Year := p.ParseDword()

							Hour := p.ParseDword()
							Minute := p.ParseDword()
							Second := p.ParseDword()

							row[2] = fmt.Sprintf("%d/%d/%d %d:%d:%d", Month, Day, Year, Hour, Minute, Second)
							row[3] = p.ParseString()

							tMap.Values = append(tMap.Values, row)
						}

						return PrintTable(tMap)
					}
				}

			case CommandMods:
				{
					if tMap, ok := HeaderMap[CommandMods]; ok {
						tMap.Values = make([][]string, 0)

						for p.Length != 0 {
							row := []string{p.ParseString(), fmt.Sprintf("0x%X", p.ParseDword64())}
							tMap.Values = append(tMap.Values, row)
						}

						return PrintTable(tMap)
					}
				}

			}
		}
	}
	return false
}

func PrintTable(tMap TableMap) {
	var sb strings.Builder

	headersInterface := make([]interface{}, len(tMap.Headers))

	for i, header := range tMap.Headers {
		headersInterface[i] = header
	}

	tbl := table.New(headersInterface...)
	format := color.New(color.FgCyan).SprintfFunc()

	tbl.WithHeaderFormatter(format)

	for _, row := range tMap.Values {
		rowInterface := make([]interface{}, len(row))

		for i, val := range row {
			rowInterface[i] = val
		}

		tbl.AddRow(rowInterface...)
	}

	fmt.Println()
	tbl.Print(&sb)
}
