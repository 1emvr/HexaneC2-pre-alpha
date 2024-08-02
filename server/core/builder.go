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
			IncludeDirectories: append(config.Builder.IncludeDirectories, "../"),
		},

		Loader: &Loader{
			RootDirectory: config.Loader.RootDirectory,
			LinkerScript:  config.Loader.LinkerScript,
			RsrcScript:    config.Loader.RsrcScript,
			RsrcBinary:    config.Loader.RsrcBinary,
			Sources:       config.Loader.Sources,
			Injection:     config.Loader.Injection,
		},
	}

	if config.Loader == nil {
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
		module.LinkerScript = "-T" + module.RootDirectory + "/" + module.LinkerScript
	}

	module.OutputName = filepath.Join(BuildPath, module.OutputName)

	if err = h.CompileSources(module); err != nil {
		return fmt.Errorf("h.CompileSources - " + err.Error())
	}

	if err = h.EmbedSectionData(module.OutputName, ".text$F", h.ConfigBytes); err != nil {
		return fmt.Errorf("h.EmbedSectionData - " + err.Error())
	}

	if err = h.CopySectionData(module.OutputName, path.Join(h.Compiler.BuildDirectory, "shellcode.bin"), ".text"); err != nil {
		return fmt.Errorf("h.CopySectionData - " + err.Error())
	}

	return nil
}

func (h *HexaneConfig) RunBuild() error {
	var err error

	if err = CreatePath(h.Compiler.BuildDirectory, os.ModePerm); err != nil {
		return fmt.Errorf("error creating payload directory - " + err.Error())
	}

	if err = h.GenerateConfigBytes(); err != nil {
		return fmt.Errorf("error generating config data - " + err.Error())
	}

	if err = GenerateHashes(HashStrings, HashHeader); err != nil {
		return fmt.Errorf("error generating string hashes - " + err.Error())
	}

	if err = h.BuildSource(); err != nil {
		return fmt.Errorf("error generating implant - " + err.Error())
	}

	return h.RunServer()
}
