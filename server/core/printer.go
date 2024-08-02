package core

import (
	"fmt"
	"github.com/olekukonko/tablewriter"
	"os"
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

func (p *Parser) ParseTable() {
	var (
		heads, vals []string
	)

	switch p.MsgType {
	case TypeCheckin:
		{
			heads = []string{"PeerId", "Hostname", "Domain", "Username", "Interfaces"}
			peerId := strconv.Itoa(int(p.PeerId))
			host := p.ParseString()

			domain := p.ParseString()
			if domain == "" {
				domain = "null"
			}
			user := p.ParseString()
			iface := p.ParseString()

			vals = []string{peerId, host, domain, user, iface}
		}

	case TypeTasking:
		{
			switch p.ParseDword() {
			case CommandDir:
				{
					heads = []string{"Mode", "Length", "LastWriteTime", "Name"}
					vals = make([]string, 0)
					row := make([]string, 4)

					for p.MsgLength != 0 {
						IsDir := p.ParseDword()

						if IsDir != 0 {
							row[0], row[1] = "dir", "n/a"

						} else {
							size := p.ParseDword64()
							row[0], row[1] = "", FormatSize(size)
						}

						row[2] = fmt.Sprintf("%d/%d/%d %d:%d:%d", p.ParseDword(), p.ParseDword(), p.ParseDword(), p.ParseDword(), p.ParseDword(), p.ParseDword())
						row[3] = p.ParseString()

						vals = append(vals, row[0], row[1], row[2], row[3])
					}
				}
			case CommandMods:
				{
					heads = []string{"ModName", "BaseAddress"}
					vals = make([]string, 0)
					row := make([]string, 2)

					for p.MsgLength != 0 {
						row[0], row[1] = p.ParseString(), fmt.Sprintf("0x%X", p.ParseDword64())
						vals = append(vals, row[0], row[1])
					}
				}
			}
		}
	}

	PrintTable(heads, vals)
	fmt.Println()
	fmt.Println()
}

func PrintTable(heads, vals []string) {

	table := tablewriter.NewWriter(os.Stdout)
	table.SetCenterSeparator("-")
	table.SetBorder(false)

	table.SetHeader(heads)
	table.Append(vals)

	fmt.Println()
	table.Render()
}
