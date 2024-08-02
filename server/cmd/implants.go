package cmd

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/rodaine/table"
	"github.com/spf13/cobra"
	"hexane_server/core"
	"strings"
)

var Implants = &cobra.Command{
	Use:   "implant",
	Short: "implant management logic",
	Long:  "implant management logic",
}

var Load = &cobra.Command{
	Use:   "load",
	Short: "load json implant configuration",
	Long:  "load json implant configuration",
	Args:  cobra.MinimumNArgs(1),

	Run: func(cmd *cobra.Command, args []string) {
		if err := core.ReadConfig(args[0]); err != nil {
			core.WrapMessage("ERR", err.Error())
		}
	},
}

var Interact = &cobra.Command{
	Use:   "i",
	Short: "interact with a specified implant by name",
	Long:  "interact with a specified implant by name",
	Args:  cobra.MinimumNArgs(1),

	Run: func(cmd *cobra.Command, args []string) {
		if err := InteractImplant(args[0]); err != nil {
			core.WrapMessage("ERR", err.Error())
		}
	},
}

var Remove = &cobra.Command{
	Use:   "rm",
	Short: "remove implant by name",
	Long:  "remove implant by name",
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

func InteractImplant(name string) error {
	return nil
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

func init() {
	Implants.AddCommand(Interact)
	Implants.AddCommand(Remove)
	Implants.AddCommand(Load)
	Implants.AddCommand(List)
}
