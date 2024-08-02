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

func init() {
	rootCmd.PersistentFlags().BoolVarP(&core.Debug, "debug", "d", false, "debug mode")
	rootCmd.PersistentFlags().BoolVarP(&core.ShowCommands, "show-commands", "c", false, "debug command mode")
	rootCmd.PersistentFlags().BoolVarP(&core.ShowConfigs, "show-configs", "j", false, "debug json configs")
	rootCmd.AddCommand(Implants)
}

func PrintChannel(cb chan core.Message, exit chan bool) {

	for {
		select {
		case x := <-exit:
			if x {
				return
			}
		case m := <-cb:
			if !core.Debug && m.MsgType == "DBG" {
				continue
			}

			fmt.Println(fmt.Sprintf("[%s] %s", m.MsgType, m.Msg))
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
	go PrintChannel(core.Cb, core.Exit)

	if err = rootCmd.ParseFlags(os.Args[1:]); err != nil {
		core.WrapMessage("ERR", err.Error())
		return
	}

	if err = core.CreatePath(core.LogsPath, os.ModePerm); err != nil {
		core.WrapMessage("ERR", err.Error())
	}
	if err = core.CreatePath(core.BuildPath, os.ModePerm); err != nil {
		core.WrapMessage("ERR", err.Error())
	}
	if core.Debug {
		core.WrapMessage("INF", "running in debug mode")
	}
	if core.ShowCommands {
		core.WrapMessage("INF", "running with command output")
	}
	if core.ShowConfigs {
		core.WrapMessage("INF", "running with json config output")
	}

	for {
		if input, err = reader.ReadString('\n'); err != nil {
			core.WrapMessage("ERR", err.Error())
			continue
		}

		input = strings.TrimSpace(input)
		if args = strings.Split(input, " "); args[0] == "exit" {
			core.Exit <- true
			break
		}

		rootCmd.SetArgs(args)

		if err = rootCmd.Execute(); err != nil {
			core.WrapMessage("ERR", err.Error())
			continue
		}
	}
}
