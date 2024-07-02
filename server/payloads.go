package main

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
	"github.com/rodaine/table"
	"strings"
)

func (h *HexaneConfig) AddServer(engine *gin.Engine, profile *HttpConfig) {

	Servers.Group++

	c := &ServerConfig{
		GroupId:   Servers.Group,
		Endpoints: profile.Endpoints,
		Address:   profile.Address,
		Port:      profile.Port,
		Handle:    engine,
		Next:      Servers.Head,
	}

	if Servers.Head != nil {
		Servers.Head.Next = Servers.Head
	}

	Servers.Head = c
	h.Server = c
}

func AddConfig(h *HexaneConfig) {

	c := &HexaneConfig{
		GroupId:     h.GroupId,
		ImplantName: h.ImplantName,
		TaskCounter: h.TaskCounter,
		Key:         h.Key,

		Implant: &ImplantConfig{
			ProfileTypeId: h.Implant.ProfileTypeId,
			Profile:       h.Implant.Profile,
			Hostname:      h.Implant.Hostname,
			Domain:        h.Implant.Domain,
			PeerId:        h.Implant.PeerId,
			IngressPipe:   h.Implant.IngressPipe,
			EgressPipe:    h.Implant.EgressPipe,
			WorkingHours:  h.Implant.WorkingHours,
			Sleeptime:     h.Implant.Sleeptime,
			Jitter:        h.Implant.Jitter,
			Killdate:      h.Implant.Killdate,
			bProxy:        h.Implant.bProxy,
		},
		Proxy: &ProxyConfig{
			Address:  h.Proxy.Address,
			Port:     h.Proxy.Port,
			Proto:    h.Proxy.Proto,
			Username: h.Proxy.Username,
			Password: h.Proxy.Password,
		},
		Compiler: &CompilerConfig{
			Debug:         h.Compiler.Debug,
			FileExtension: h.Compiler.FileExtension,
		},
		UserSession: &HexaneSession{
			username: h.UserSession.username,
			admin:    h.UserSession.admin,
		},
	}

	if Payloads.Head != nil {
		c.Next = Payloads.Head
	}

	Payloads.Head = c
}

func RemoveImplantByPeerId(pid uint32) error {

	var Prev *HexaneConfig
	var Head = Payloads.Head

	for Head != nil {
		if Head.Implant.PeerId == pid {

			if Head.Next == nil {
				if Head.Server != nil && Head.Server.SigTerm != nil {
					Head.Server.SigTerm <- true
				} else {
					WrapMessage("WRN", "A server/channel was not found for this implant. Implant will still be removed")
				}
			}
			if Prev == nil {
				Payloads.Head = Head.Next
			} else {
				Prev.Next = Head.Next
			}
			break

		}
		Prev = Head
		Head = Head.Next
	}

	WrapMessage("INF", "implant removed")
	return nil
}

func RemoveImplantByName(name string) error {

	var Prev *HexaneConfig
	var Head = Payloads.Head

	for Head != nil {
		if strings.EqualFold(Head.ImplantName, name) {

			if Head.Next == nil {
				if Head.Server != nil && Head.Server.SigTerm != nil {
					Head.Server.SigTerm <- true
				} else {
					WrapMessage("WRN", "A server/channel was not found for this implant. Implant will still be removed")
				}
			}
			if Prev == nil {
				Payloads.Head = Head.Next
			} else {
				Prev.Next = Head.Next
			}
			break

		}
		Prev = Head
		Head = Head.Next
	}

	WrapMessage("INF", "implant removed")
	return nil
}

func GetConfigByGID(gid int) *HexaneConfig {
	var Head = Payloads.Head

	for Head != nil {
		if Head.GroupId == gid {
			return Head
		}
		Head = Head.Next
	}
	return nil
}

func GetConfigByPeerId(pid uint32) *HexaneConfig {
	var Head = Payloads.Head

	for Head != nil {
		WrapMessage("DBG", fmt.Sprintf(" checking %d against %d\n", pid, Head.Implant.PeerId))

		if Head.Implant.PeerId == pid {
			return Head
		}
		Head = Head.Next
	}

	WrapMessage("ERR", "requested config was not found by pid")
	return nil
}

func GetGIDByPeerName(name string) int {
	var Head = Payloads.Head

	for Head != nil {

		WrapMessage("DBG", fmt.Sprintf("checking %s against %s", name, Head.ImplantName))
		if Head.ImplantName == name {
			return Head.GroupId
		}
		Head = Head.Next
	}

	WrapMessage("ERR", "requested config was not found by name")
	return 0
}

func GetPeerNameByGID(gid int) *HexaneConfig {
	var Head = Payloads.Head

	for Head != nil {
		if Head.GroupId == gid {
			return Head
		}
		Head = Head.Next
	}

	WrapMessage("ERR", "requested config was not found by name")
	return nil
}

func CallbackList() {
	var (
		address,
		domain,
		profile,
		proxy string
	)

	var Head = Payloads.Head

	hFmt := color.New(color.FgCyan).SprintfFunc()
	tbl := table.New("gid", "pid", "name", "debug", "type", "address", "hostname", "domain", "proxy", "user", "active")

	tbl.WithHeaderFormatter(hFmt)

	if Head == nil {
		WrapMessage("INF", "no active implants available")
		return

	} else {
		fmt.Print(`
			-- IMPLANTS -- 
`)
		for Head != nil {
			if Head.Implant.ProfileTypeId == TRANSPORT_HTTP {

				address = fmt.Sprintf("%s:%d", Head.Implant.Profile.(*HttpConfig).Address, Head.Implant.Profile.(*HttpConfig).Port)
				profile = "http"

				if Head.Implant.bProxy {
					proxy = fmt.Sprintf("%s%s:%s", Head.Proxy.Proto, Head.Proxy.Address, Head.Proxy.Port)
				} else {
					proxy = "null"
				}
				if Head.Implant.Domain != "" {
					domain = Head.Implant.Domain
				} else {
					domain = "null"
				}
			}
			tbl.AddRow(Head.GroupId, Head.Implant.PeerId, Head.ImplantName, Head.Compiler.Debug, profile, address, Head.Implant.Hostname, domain, proxy, Head.UserSession.username, Head.Active)
			Head = Head.Next
		}
	}
	tbl.Print()
	fmt.Println()
}
