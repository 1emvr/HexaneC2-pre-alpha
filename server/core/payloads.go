package core

import (
	"fmt"
	"github.com/gin-gonic/gin"
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
			ProxyBool:     h.Implant.ProxyBool,
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
			Username: h.UserSession.Username,
			Admin:    h.UserSession.Admin,
		},
	}

	if Payloads.Head != nil {
		c.Next = Payloads.Head
	}

	Payloads.Head = c
}

func GetImplantByName(name string) *HexaneConfig {
	var Head = Payloads.Head

	for Head != nil {
		if Head.ImplantName == name {
			return Head
		}
		Head = Head.Next
	}

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