package main

import (
	"bufio"
	"fmt"
	"github.com/spf13/cobra"
	"hexane_server/core"
	"os"
	"strings"
)

var (
	debug    bool
	cb       = make(chan core.Callback)
	payloads = new(core.HexanePayloads)
	servers  = new(core.ServerList)
	session  = &core.HexaneSession{
		username: "lemur",
		admin:    true,
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

var implants = &cobra.Command{
	Use:   "implant",
	Short: "implant management logic",
	Long:  "implant management logic",
}

func CallbackListener(cb chan core.Callback) {
	for {
		select {
		case m := <-cb:
			if !debug && m.typ == "DBG" {
				continue
			}
			fmt.Println(fmt.Sprintf("[%s] %s", m.typ, m.msg))

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

	go CallbackListener(cb)
	defer close(cb)

	if len(os.Args) > 1 && os.Args[1] == "DEBUG" {
		debug = true
		core.WrapMessage("DBG", "launching in debug mode")

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
	// global for your application.
	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.hexane_server.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "debug mode")
	rootCmd.AddCommand(implants)
}
