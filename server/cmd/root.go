package cmd

import (
	"bufio"
	"fmt"
	"github.com/spf13/cobra"
	"hexane_server/core"
	"os"
	"strings"
)

var ()

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

func init() {
	rootCmd.PersistentFlags().BoolVarP(&core.Debug, "debug", "d", false, "debug mode")
	rootCmd.PersistentFlags().BoolVarP(&core.ShowCommands, "show_commands", "c", false, "debug command mode")
	rootCmd.AddCommand(Implants)
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

func Run() {
	var (
		err    error
		input  string
		args   []string
		reader = bufio.NewReader(os.Stdin)
	)

	fmt.Println(banner)

	go CallbackListener(core.Cb)
	defer close(core.Cb)

	if err = rootCmd.ParseFlags(os.Args[1:]); err != nil {
		core.WrapMessage("ERR", err.Error())
		return
	}

	if core.Debug {
		core.WrapMessage("INF", "running in debug mode")
	}
	if core.ShowCommands {
		core.WrapMessage("INF", "running with command output")
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
			continue
		}
	}
}
