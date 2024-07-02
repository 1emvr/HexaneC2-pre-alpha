package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var banner = `
██╗  ██╗███████╗██╗  ██╗ █████╗ ███╗   ██╗███████╗     ██████╗██████╗ 
██║  ██║██╔════╝╚██╗██╔╝██╔══██╗████╗  ██║██╔════╝    ██╔════╝╚════██╗
███████║█████╗   ╚███╔╝ ███████║██╔██╗ ██║█████╗█████╗██║      █████╔╝
██╔══██║██╔══╝   ██╔██╗ ██╔══██║██║╚██╗██║██╔══╝╚════╝██║     ██╔═══╝ 
██║  ██║███████╗██╔╝ ██╗██║  ██║██║ ╚████║███████╗    ╚██████╗███████╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝     ╚═════╝╚══════╝`

var s = &HexaneSession{
	username: "lemur",
	admin:    true,
}

var debug = true
var cwd string

var cb = make(chan Callback)
var Payloads = new(HexanePayloads)
var Servers = new(ServerList)

type Callback struct {
	typ string
	msg string
}

func CallbackListener(cb chan Callback) {
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

func main() {
	var (
		err     error
		scanner *bufio.Scanner
	)

	fmt.Println(banner)
	go CallbackListener(cb)
	defer close(cb)

	scanner = bufio.NewScanner(os.Stdin)

	for {
		fmt.Println()
		if scanner.Scan() {

			args := strings.Split(scanner.Text(), " ")
			switch args[0] {
			case "exit":
				{
					os.Exit(0)
				}
			case "help":
				{
					WrapMessage("INF", "Usage: hahaha")
					continue
				}
			case "implant":
				{
					if len(args) >= 2 {

						switch args[1] {
						case "ls":
							{
								CallbackList()
								continue
							}
						case "load":
							{
								if len(args) != 3 {
									WrapMessage("ERR", "invalid arguments")
									continue

								} else {
									if err = ReadConfig(cwd, args[2]); err != nil {
										WrapMessage("ERR", fmt.Sprintf("implant load error: %s\n", err))
									}
									continue
								}
							}
						case "rm":
							{
								var pid int

								if len(args) != 3 {
									WrapMessage("ERR", "invalid arguments")
									continue

								} else {
									if pid, err = strconv.Atoi(args[2]); err != nil {
										if err = RemoveImplantByName(args[2]); err != nil {
											WrapMessage("ERR", fmt.Sprintf("error removing implant: %s\n", err))
										}
										continue
									}
									if err = RemoveImplantByPeerId(uint32(pid)); err != nil {
										WrapMessage("ERR", fmt.Sprintf("error removing implant: %s\n", err))
									}
									continue
								}
							}
						default:
							{
								WrapMessage("ERR", "invalid arguments")
								continue
							}
						}
					}
				}
			default:
				WrapMessage("ERR", "invalid arguments")
				continue
			}
		}
	}
}
