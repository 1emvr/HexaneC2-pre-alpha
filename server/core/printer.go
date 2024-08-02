package core

import (
	"bytes"
	"fmt"
	"github.com/olekukonko/tablewriter"
	"os"
	"strconv"
)

func (p *Parser) ParseTable(writer *WriteChannel) {
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

	writer.PrintTable(heads, vals)
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

func (w *WriteChannel) PrintTable(heads, vals []string) {
	if !w.IsActive {
		return
	}

	w.Table = tablewriter.NewWriter(os.Stdout)
	w.Table.SetCenterSeparator("-")
	w.Table.SetBorder(false)

	w.Table.SetHeader(heads)
	w.Table.Append(vals)

	fmt.Println()
	w.Table.Render()
	w.Buffer.Reset()

	fmt.Println()
	fmt.Println()
}
