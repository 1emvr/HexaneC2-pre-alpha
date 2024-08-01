package core

import "os"

var (
	Debug        = false
	ShowCommands = false
	ShowConfigs  = false

	Cb             = make(chan Message)
	Exit           = make(chan bool)
	HexanePayloads = new(Payloads)
	HexaneServers  = new(ServerList)

	// HexaneSession todo: add user sessions/authentication
	HexaneSession = &Session{
		Username: "lemur",
		Admin:    true,
	}

	FSTAT_RW  = os.O_RDWR | os.O_APPEND
	Useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
)
