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
		Prev *core.HexaneConfig
		Head = core.Payloads.Head
	)

	for Head != nil {
		if strings.EqualFold(Head.ImplantName, name) {

			if Head.Next == nil {
				if Head.ServerCFG != nil && Head.ServerCFG.SigTerm != nil {
					Head.ServerCFG.SigTerm <- true

				} else {
					core.WrapMessage("WRN", "A server/channel was not found for this implant. Implant will still be removed")
				}
			}

			if Prev == nil {
				core.Payloads.Head = Head.Next
			} else {
				Prev.Next = Head.Next
			}

			break
		}

		Prev = Head
		Head = Head.Next
	}

	core.WrapMessage("ERR", "implant not found")
	return nil
}

func ListImplants() error {
	var (
		Head    = core.Payloads.Head
		address string
		domain  string
		profile string
		proxy   string
	)

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
			if Head.ImplantCFG.ProfileTypeId == core.TRANSPORT_HTTP {

				address = fmt.Sprintf("%s:%d", Head.ImplantCFG.Profile.(*core.HttpConfig).Address, Head.ImplantCFG.Profile.(*core.HttpConfig).Port)
				profile = "http"

				if Head.ImplantCFG.ProxyBool {
					proxy = fmt.Sprintf("%s%s:%s", Head.ProxyCFG.Proto, Head.ProxyCFG.Address, Head.ProxyCFG.Port)
				} else {
					proxy = "null"
				}

				if Head.ImplantCFG.Domain != "" {
					domain = Head.ImplantCFG.Domain
				} else {
					domain = "null"
				}
			}

			implantTable.AddRow(Head.GroupId, Head.PeerId, Head.ImplantName, Head.CompilerCFG.Debug, profile, address, Head.ImplantCFG.Hostname, domain, proxy, Head.UserSession.Username, Head.Active)
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
