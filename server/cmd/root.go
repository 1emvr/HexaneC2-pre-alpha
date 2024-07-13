package cmd

import (
	"bufio"
	"fmt"
	"github.com/spf13/cobra"
	"hexane_server/core"
	"os"
	"strings"
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
			if !core.Debug && m.MsgType == "DBG" {
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

	go CallbackListener(core.Cb)
	defer close(core.Cb)

	if len(os.Args) > 1 && os.Args[1] == "DEBUG" {
		core.Debug = true
		core.WrapMessage("INF", "launching in debug mode")

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
	rootCmd.PersistentFlags().BoolVarP(&core.Debug, "debug", "d", false, "debug mode")
	rootCmd.AddCommand(Implants)
}

