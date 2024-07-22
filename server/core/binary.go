package core

import (
	"bufio"
	"context"
	"debug/pe"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

func (h *HexaneConfig) GenerateIncludes(incs []string) string {
	var list string

	for _, inc := range incs {
		list += fmt.Sprintf(" -I%s ", inc)
	}

	return list
}

func (h *HexaneConfig) GenerateArguments(args []string) string {
	var (
		list string
	)

	for _, arg := range args {
		list += fmt.Sprintf(" %s ", arg)
	}
	return list
}

func (h *HexaneConfig) GenerateDefinitions(defs map[string][]byte) string {
	var list string

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

func GenerateHashes(stringsFile string, outFile string) error {
	var (
		err     error
		strFile *os.File
	)

	if strFile, err = os.Open(stringsFile); err != nil {
		return err
	}

	defer func() {
		if err = strFile.Close(); err != nil {
			WrapMessage("ERR", err.Error())
		}
	}()

	hashes := make([]string, 0)
	scanner := bufio.NewScanner(strFile)

	for scanner.Scan() {
		line := scanner.Text()
		hash := GetHashFromString(line)
		hashes = append(hashes, hash)
	}

	if err = scanner.Err(); err != nil {
		return err
	}

	text := strings.Join(hashes, "\n")
	if err = WriteFile(outFile, []byte(text)); err != nil {
		return err
	}

	return nil
}

func (h *HexaneConfig) EmbedSectionData(readPath string, targetSection string, data []byte) error {
	var (
		readFile *os.File
		peFile   *pe.File
		section  *pe.Section
		secData  []byte
		err      error
	)

	if readFile, err = os.OpenFile(readPath, FstatRW, 0644); err != nil {
		return err
	}
	defer func() {
		if err = readFile.Close(); err != nil {
			WrapMessage("ERR", err.Error())
		}
	}()

	if peFile, err = pe.NewFile(readFile); err != nil {
		return err
	}
	defer func() {
		if err = peFile.Close(); err != nil {
			WrapMessage("ERR", err.Error())
		}
	}()

	for _, s := range peFile.Sections {
		if s.Name == targetSection {
			section = s
			break
		}
	}

	if section == nil {
		return fmt.Errorf("section %s not found in %s", targetSection, readPath)
	}

	if uint32(len(data)) > section.Size {
		return fmt.Errorf("section %s is not large enough in %s", targetSection, readPath)
	}

	if secData, err = section.Data(); err != nil {
		return err
	}

	newSection := make([]byte, len(data))
	copy(newSection, secData)
	copy(newSection, data)

	if _, err = readFile.Seek(int64(section.Offset), os.SEEK_SET); err != nil {
		return err
	}

	if _, err = readFile.Write(newSection); err != nil {
		return err
	}

	return nil
}

func (h *HexaneConfig) CopySectionData(readPath string, outPath string, targetSection string) error {
	var (
		readFile *os.File
		peFile   *pe.File
		section  *pe.Section
		err      error
	)

	if readFile, err = os.Open(readPath); err != nil {
		return err
	}
	defer func() {
		if err = readFile.Close(); err != nil {
			WrapMessage("ERR", err.Error())
		}
	}()

	if peFile, err = pe.NewFile(readFile); err != nil {
		return err
	}

	for _, s := range peFile.Sections {
		if s.Name == targetSection {
			section = s
			break
		}
	}

	if section == nil {
		return fmt.Errorf("%s section was not found", targetSection)
	}

	outData := make([]byte, section.Size)

	if _, err = readFile.ReadAt(outData, int64(section.Offset)); err != nil {
		return err
	}

	if err = WriteFile(outPath, outData); err != nil {
		return err
	}

	return nil
}

func (h *HexaneConfig) CompileObject(command, output string, targets, flags, includes []string, definitions map[string][]byte) error {
	var err error

	if definitions == nil {
		definitions = make(map[string][]byte)
	}

	if h.CompilerCFG.Debug {
		definitions["DEBUG"] = nil
	}

	if includes != nil {
		command += h.GenerateIncludes(includes)
	}

	if targets != nil {
		command += h.GenerateArguments(targets)
	}

	if flags != nil {
		command += h.GenerateArguments(flags)
	}

	if definitions != nil {
		for k, v := range definitions {
			command += h.GenerateDefinitions(map[string][]byte{k: v})
		}
	}

	command += fmt.Sprintf(" -o %s ", output)

	if err = h.RunCommand(command); err != nil {
		return err
	}
	return nil
}

func (h *HexaneConfig) BuildSources(module *Object) error {
	var (
		err   error
		flags []string
		wg    sync.WaitGroup
	)

	errCh := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	srcPath := filepath.Join(module.RootDirectory, "src")
	for _, src := range module.Sources {
		wg.Add(1)

		go func(src string) {
			var ()
			defer wg.Done()

			target := filepath.Join(srcPath, src)
			obj := filepath.Join(BuildPath, src+".o")

			select {
			case <-ctx.Done():
				return

			default:
				switch filepath.Ext(target) {
				case ".asm":
					obj = module.OutputName
					flags = []string{"-f win64"}

					err = h.CompileObject(h.CompilerCFG.Assembler, obj, []string{target}, flags, nil, nil)

				case ".cpp":
					flags = []string{"-c"}
					flags = append(flags, h.CompilerCFG.Flags...)

					err = h.CompileObject(h.CompilerCFG.Mingw, obj, []string{target}, flags, module.IncludeDirectories, nil)
				}
			}

			if err != nil {
				select {
				case errCh <- err:
					cancel()

				case <-ctx.Done():
					err = nil
				}
				return
			}

			module.Components = append(module.Components, obj)
		}(src)
	}

	go func() {
		wg.Wait()
		close(errCh)
	}()

	if err = <-errCh; err != nil {
		return err
	}

	return nil
}

func (h *HexaneConfig) ExecuteBuildType(module *Object) error {
	var (
		err       error
		flags     []string
		transport string
	)

	module.OutputName = filepath.Join(BuildPath, module.OutputName)
	if module.Linker != "" {
		flags = append(flags, "-T"+module.Linker)
	}

	defs := h.CompilerCFG.Definitions
	if module.Implant {
		if transport, err = h.GetTransportType(); err != nil {
			return err
		}

		defs = MergeMaps(defs, map[string][]byte{transport: nil})
	}
	switch module.Type {
	case "resource":
		WrapMessage("DBG", "building resource file from json config")
		return h.RunCommand(h.CompilerCFG.Windres + " -O coff " + module.RsrcScript + " -DRSRCDATA=\"" + module.RsrcBinary + "\" -o " + module.OutputName)

	case "static":
		WrapMessage("DBG", "building static library from json config")
		return h.RunCommand(h.CompilerCFG.Ar + " rcs " + module.OutputName + " " + strings.Join(module.Components, " "))

	case "dynamic":
		WrapMessage("DBG", "building dynamic library from json config")

		flags = append(flags, "-shared")
		flags = append(flags, h.CompilerCFG.Flags...)

		return h.CompileObject(h.CompilerCFG.Linker, module.OutputName, module.Components, flags, module.IncludeDirectories, defs)

	case "object":
		WrapMessage("DBG", "building object file from json config")

		flags = append(flags, h.CompilerCFG.Flags...)
		return h.CompileObject(h.CompilerCFG.Mingw, module.OutputName, module.Components, flags, module.IncludeDirectories, defs)

	default:
		return fmt.Errorf("unknown build type: %s", module.Type)
	}
}

func (h *HexaneConfig) StripSymbols(output string) error {
	return h.RunCommand(h.CompilerCFG.Strip + " " + output)
}

func (h *HexaneConfig) RunCommand(cmd string) error {
	var (
		Command *exec.Cmd
		Log     *os.File
		LogName string
		err     error
	)

	LogName = filepath.Join(LogsPath, strconv.Itoa(int(h.PeerId))+"-error.log")
	if Log, err = os.Create(LogName); err != nil {
		return err
	}

	defer func() {
		if err = Log.Close(); err != nil {
			WrapMessage("ERR", err.Error())
		}
	}()

	Command = exec.Command("bash", "-c", cmd)
	Command.Stdout = Log
	Command.Stderr = Log

	if ShowCommands {
		WrapMessage("DBG", "running command : "+Command.String()+"\n")
	}

	if err = Command.Run(); err != nil {
		return fmt.Errorf("compilation error. Check %s for details", LogName)
	}

	return nil
}
