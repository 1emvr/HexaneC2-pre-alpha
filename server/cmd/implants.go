package cmd

import (
	"bufio"
	"fmt"
	"github.com/fatih/color"
	"github.com/rodaine/table"
	"github.com/spf13/cobra"
	"hexane_server/core"
	"os"
	"strings"
)

var Implants = &cobra.Command{
	Use:   "implant",
	Short: "implant management logic",
	Long:  "implant management logic",
}

var Load = &cobra.Command{
	Use:   "load",
	Short: "load json implant config",
	Long:  "load json implant config",
	Args:  cobra.MinimumNArgs(1),

	Run: func(cmd *cobra.Command, args []string) {
		if err := core.ReadConfig(args[0]); err != nil {
			core.WrapMessage("ERR", err.Error())
		}
	},
}

var Interact = &cobra.Command{
	Use:   "i",
	Short: "interact with an implant by name",
	Long:  "interact with an implant by name",
	Args:  cobra.MinimumNArgs(1),

	Run: func(cmd *cobra.Command, args []string) {
		var (
			err    error
			config *core.HexaneConfig
		)
		if config := core.GetImplantByName(args[0]); config == nil {
			core.WrapMessage("ERR", fmt.Sprintf("failed to get config for %s", args[0]))
			return
		}
		if err = UserInterface(config); err != nil {
			core.WrapMessage("ERR", err.Error())
			return
		}
	},
}

var Remove = &cobra.Command{
	Use:   "rm",
	Short: "remove an implant by name",
	Long:  "remove an implant by name",
	Args:  cobra.MinimumNArgs(1),

	Run: func(cmd *cobra.Command, args []string) {
		if err := RemoveImplantByName(args[0]); err != nil {
			core.WrapMessage("ERR", err.Error())
		}
	},
}

var List = &cobra.Command{
	Use:   "ls",
	Short: "list all loaded implants",
	Long:  "list all loaded implants",
	Args:  cobra.NoArgs,

	Run: func(cmd *cobra.Command, args []string) {
		if err := ListImplants(); err != nil {
			core.WrapMessage("ERR", err.Error())
		}
	},
}

func RemoveImplantByName(name string) error {
	var (
		err  error
		Prev *core.HexaneConfig
	)

	Head := core.HexanePayloads.Head

	for Head != nil {
		if strings.EqualFold(Head.UserConfig.Builder.OutputName, name) {

			if Head.Next == nil {
				var profile core.Http

				if err = core.MapToStruct(Head.UserConfig.Network.Config, &profile); err != nil {
					return err
				}

				if profile.SigTerm != nil {
					profile.SigTerm <- true
				} else {
					core.WrapMessage("WRN", "A server/channel was not found for this implant. Implant will still be removed")
				}
			}

			if Prev == nil {
				core.HexanePayloads.Head = Head.Next
			} else {
				Prev.Next = Head.Next
			}

			core.WrapMessage("INF", "implant removed")
			return nil
		}

		Prev = Head
		Head = Head.Next
	}

	core.WrapMessage("ERR", "implant not found")
	return nil
}

func ListImplants() error {
	var (
		err     error
		address string
		domain  string
		netType string
		proxy   string
	)

	Head := core.HexanePayloads.Head
	formatter := color.New(color.FgCyan).SprintfFunc()

	implantTable := table.New("gid", "pid", "name", "debug", "type", "address", "hostname", "domain", "proxy", "user", "active")
	implantTable.WithHeaderFormatter(formatter)

	if Head == nil {
		return fmt.Errorf("no active implants available")

	} else {
		fmt.Print(`
			-- IMPLANTS -- 
`)
		for Head != nil {
			if Head.Implant.ProfileTypeId == core.TRANSPORT_HTTP {
				var config core.Http

				if err = core.MapToStruct(Head.UserConfig.Network.Config, &config); err != nil {
					return err
				}

				address = fmt.Sprintf("%s:%d", config.Address, config.Port)
				netType = "http"

				if Head.Implant.ProxyBool {
					proxy = fmt.Sprintf("%s%s:%s", config.Proxy.Proto, config.Proxy.Address, config.Proxy.Port)
				} else {
					proxy = "null"
				}

				if config.Domain != "" {
					domain = config.Domain
				} else {
					domain = "null"
				}
			} else if Head.Implant.ProfileTypeId == core.TRANSPORT_PIPE {
				config := Head.UserConfig.Network.Config.(*core.Smb)

				address = config.EgressPipename
				netType = "smb"
			}

			implantTable.AddRow(Head.GroupId, Head.PeerId, Head.UserConfig.Builder.OutputName, Head.Compiler.Debug, netType, address, Head.Implant.Hostname, domain, proxy, Head.UserSession.Username, Head.Active)
			Head = Head.Next
		}
	}

	implantTable.Print()
	fmt.Println()

	return nil
}

func UserInterface(config *core.HexaneConfig) error {
	var (
		err   error
		input string
	)

	reader := bufio.NewReader(os.Stdin)
	for {
		if input, err = reader.ReadString('\n'); err != nil {
			return err
		}
		if input == "exit" {
			break
		}
		if config.CommandChan == nil {
			return fmt.Errorf("%s command channel is not ready", config.PeerId)
		}
		select {
		case config.CommandChan <- input:
			core.WrapMessage("INF", "command queued")
		default:
			core.WrapMessage("INF", "command queue is full. please wait for processing...")
		}
		// todo: print from config RespChan. Only print when interacting with selected implant.
	}

	return nil
}

func init() {
	Implants.AddCommand(Interact)
	Implants.AddCommand(Remove)
	Implants.AddCommand(Load)
	Implants.AddCommand(List)
}
