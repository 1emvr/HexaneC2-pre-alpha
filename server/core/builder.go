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

func (h *HexaneConfig) BuildModule(cfgName string) error {
	var (
		err        error
		components []string
		includes   []string
		jsonCfg    *ModuleConfig
	)

	if jsonCfg, err = GetModuleConfig(cfgName); err != nil {
		return err
	}

	if jsonCfg.RootDir == "" || jsonCfg.Sources == nil {
		return fmt.Errorf("root directory needs provided")
	}

	if jsonCfg.Sources == nil {
		return fmt.Errorf("source files need to be provided")
	}

	if jsonCfg.OutputDir != "" {
		if err = CreateTemp(jsonCfg.OutputDir); err != nil {
			return err
		}
	} else {
		jsonCfg.OutputDir = h.Compiler.BuildDirectory
	}

	if jsonCfg.Dependencies != nil {
		for _, dep := range jsonCfg.Dependencies {
			components = append(components, dep)
		}
	}

	if jsonCfg.PreBuildDependencies != nil {
		for _, dep := range jsonCfg.PreBuildDependencies {
			if err = h.BuildModule(dep); err != nil {
				return err
			}
		}
	}

	for _, src := range jsonCfg.Sources {

		srcPath := filepath.Join(jsonCfg.RootDir, "src")
		incPath := filepath.Join(jsonCfg.RootDir, "include")
		dep := filepath.Join(jsonCfg.OutputDir, src+".o")

		if err = SearchFile(srcPath, src); err != nil {
			return fmt.Errorf("could not find %s in %s", src, srcPath)
		}

		if jsonCfg.Includes != nil {
			for _, inc := range jsonCfg.Includes {
				if err = SearchFile(incPath, inc); err != nil {
					return fmt.Errorf("could not find %s in %s", inc, incPath)
				}

				includes = append(includes, inc)
			}
		}

		inc := h.GenerateIncludes(includes)
		if err = h.CompileFile(src, dep, inc, jsonCfg.Linker); err != nil {
			return err
		}

		components = append(components, dep)
	}

	return h.ExecuteBuild(jsonCfg, cfgName, components, includes)
}

func (h *HexaneConfig) RunBuild() error {

	WrapMessage("DBG", "creating payload directory")
	if err := os.MkdirAll(h.Compiler.BuildDirectory, os.ModePerm); err != nil {
		return err
	}

	WrapMessage("DBG", "generating config")
	if err := h.GenerateConfigBytes(); err != nil {
		return err
	}

	WrapMessage("DBG", "generating hashes")
	if err := GenerateHashes(HashStrings, HashHeader); err != nil {
		return err
	}

	// generate corelib
	if err := SearchFile(Libs, "corelib.a"); err != nil {
		if err.Error() == FileNotFound.Error() {

			WrapMessage("DBG", "generating corelib\n")
			if err := h.BuildModule(path.Join(Corelib, "corelib.json")); err != nil {
				return err
			}
		} else {
			return err
		}
	}

	// generate implant
	WrapMessage("DBG", "generating implant\n")
	if err := h.BuildModule(path.Join(ImplantPath, "implant.json")); err != nil {
		return err
	}

	WrapMessage("DBG", "embedding implant config data")
	if err := h.EmbedSectionData(path.Join(h.Compiler.BuildDirectory, "build")+"/implant.o", ".text$F", h.ConfigBytes); err != nil {
		return err
	}

	WrapMessage("DBG", "extracting shellcode")
	if err := h.CopySectionData(path.Join(h.Compiler.BuildDirectory, "build")+"/implant.o", path.Join(h.Compiler.BuildDirectory, "shellcode.bin"), ".text"); err != nil {
		return err
	}

	// generate injectlib + loader
	if h.Implant.Injection != nil {
		WrapMessage("DBG", "generating injectlib\n")
		if err := h.BuildModule(path.Join(Injectlib, h.Implant.Injection.ConfigName)); err != nil {
			return err
		}

		WrapMessage("DBG", "embedding injectlib config")
		if err := h.EmbedSectionData(path.Join(h.Compiler.BuildDirectory, h.Implant.Injection.Config.OutputName), ".text$F", h.ConfigBytes); err != nil {
			return err
		}

		WrapMessage("DBG", "generating loader dll")
		if err := h.BuildLoader(path.Join(LoaderPath, "loader.json")); err != nil {
			return err
		}
	}

	AddConfig(h)
	go h.HttpServerHandler()

	time.Sleep(time.Millisecond * 500)
	WrapMessage("INF", fmt.Sprintf("%s ready!", h.ImplantName))

	return nil
}
