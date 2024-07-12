package cmd

import (
	"bufio"
	"fmt"
	"github.com/spf13/cobra"
	"hexane_server/core"
	"os"
	"strings"
)

var (
	Debug    bool
	Cb       = make(chan core.Callback)
	Payloads = new(core.HexanePayloads)
	Servers  = new(core.ServerList)
	Session  = &core.HexaneSession{
		Username: "lemur",
		Admin:    true,
	}

)

var banner = `
██╗  ██╗███████╗██╗  ██╗ █████╗ ███╗   ██╗███████╗     ██████╗██████╗ 
██║  ██║██╔════╝╚██╗██╔╝██╔══██╗████╗  ██║██╔════╝    ██╔════╝╚════██╗
███████║█████╗   ╚███╔╝ ███████║██╔██╗ ██║█████╗█████╗██║      █████╔╝
██╔══██║██╔══╝   ██╔██╗ ██╔══██║██║╚██╗██║██╔══╝╚════╝██║     ██╔═══╝ 
██║  ██║███████╗██╔╝ ██╗██║  ██║██║ ╚████║███████╗    ╚██████╗███████╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝     ╚═════╝╚══════╝`

var rootCmd = &cobra.Command{
	Use:   "HexaneC2",
	Short: "Minimal command & control framework",
	Long:  "Minimal command & control framework",
}

func CallbackListener(cb chan core.Callback) {
	for {
		select {
		case m := <-cb:
			if !Debug && m.MsgType == "DBG" {
				continue
			}
			fmt.Println(fmt.Sprintf("[%s] %s", m.MsgType, m.Msg))

		default:
			continue
		}
	}
}

func Execute() {
	var (
		err    error
		input  string
		args   []string
		reader = bufio.NewReader(os.Stdin)
	)

	fmt.Println(banner)

	go CallbackListener(Cb)
	defer close(Cb)

	if len(os.Args) > 1 && os.Args[1] == "DEBUG" {
		Debug = true
		core.WrapMessage("INF", "launching in debug mode")

	} else {
		core.WrapMessage("ERR", fmt.Sprintf("unknown flag '%s'", os.Args[1]))
	}

	if err = rootCmd.ParseFlags(os.Args[1:]); err != nil {
		core.WrapMessage("ERR", err.Error())
		return
	}

	for {
		if input, err = reader.ReadString('\n'); err != nil {
			core.WrapMessage("ERR", err.Error())
			continue
		}

		input = strings.TrimSpace(input)
		if args = strings.Split(input, " "); args[0] == "exit" {
			break
		}

		rootCmd.SetArgs(args)

		if err = rootCmd.Execute(); err != nil {
			core.WrapMessage("ERR", err.Error())
			os.Exit(1)
		}
	}
}


func init() {
	rootCmd.PersistentFlags().BoolVarP(&Debug, "debug", "d", false, "debug mode")
	rootCmd.AddCommand(Implants)
}
