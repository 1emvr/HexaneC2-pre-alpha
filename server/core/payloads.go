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
	h.ServerCFG = c
}

func AddConfig(h *HexaneConfig) {

	c := &HexaneConfig{
		GroupId:       h.GroupId,
		PeerId:        h.PeerId,
		ImplantName:   h.ImplantName,
		CurrentTaskId: h.CurrentTaskId,
		Key:           h.Key,

		ImplantCFG: &ImplantConfig{
			ProfileTypeId: h.ImplantCFG.ProfileTypeId,
			Profile:       h.ImplantCFG.Profile,
			Hostname:      h.ImplantCFG.Hostname,
			Domain:        h.ImplantCFG.Domain,
			IngressPipe:   h.ImplantCFG.IngressPipe,
			EgressPipe:    h.ImplantCFG.EgressPipe,
			WorkingHours:  h.ImplantCFG.WorkingHours,
			Sleeptime:     h.ImplantCFG.Sleeptime,
			Jitter:        h.ImplantCFG.Jitter,
			Killdate:      h.ImplantCFG.Killdate,
			ProxyBool:     h.ImplantCFG.ProxyBool,
		},
		ProxyCFG: &ProxyConfig{
			Address:  h.ProxyCFG.Address,
			Port:     h.ProxyCFG.Port,
			Proto:    h.ProxyCFG.Proto,
			Username: h.ProxyCFG.Username,
			Password: h.ProxyCFG.Password,
		},
		CompilerCFG: &CompilerConfig{
			Debug:         h.CompilerCFG.Debug,
			FileExtension: h.CompilerCFG.FileExtension,
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
		WrapMessage("DBG", fmt.Sprintf(" checking %d against %d\n", pid, Head.PeerId))

		if Head.PeerId == pid {
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
