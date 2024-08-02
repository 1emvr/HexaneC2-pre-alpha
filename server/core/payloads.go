package core

func AddServer(profile *Http) {

	HexaneServers.Group++

	c := &Http{
		Endpoints: profile.Endpoints,
		Address:   profile.Address,
		Port:      profile.Port,
		Handle:    profile.Handle,
		SigTerm:   profile.SigTerm,
		GroupId:   HexaneServers.Group,
		Next:      HexaneServers.Head,
	}

	HexaneServers.Head = c
}

func AddConfig(h *HexaneConfig) {

	if HexanePayloads.Head != nil {
		h.Next = HexanePayloads.Head
	}

	HexanePayloads.Head = h
}

func GetImplantByName(name string) *HexaneConfig {
	var Head = HexanePayloads.Head

	for Head != nil {
		if Head.UserConfig.Builder.OutputName == name {
			return Head
		}
		Head = Head.Next
	}

	return nil
}

func GetConfigByGID(gid int) *HexaneConfig {
	var Head = HexanePayloads.Head

	for Head != nil {
		if Head.GroupId == gid {
			return Head
		}
		Head = Head.Next
	}
	return nil
}

func GetConfigByPeerId(pid uint32) *HexaneConfig {
	var Head = HexanePayloads.Head

	for Head != nil {
		if Head.PeerId == pid {
			return Head
		}
		Head = Head.Next
	}

	WrapMessage("ERR", "requested config was not found by pid")
	return nil
}

func GetGIDByPeerName(name string) int {
	var Head = HexanePayloads.Head

	for Head != nil {
		if Head.UserConfig.Builder.OutputName == name {
			return Head.GroupId
		}
		Head = Head.Next
	}

	WrapMessage("ERR", "requested config was not found by name")
	return 0
}

func GetPeerNameByGID(gid int) *HexaneConfig {
	var Head = HexanePayloads.Head

	for Head != nil {
		if Head.GroupId == gid {
			return Head
		}
		Head = Head.Next
	}

	WrapMessage("ERR", "requested config was not found by name")
	return nil
}
