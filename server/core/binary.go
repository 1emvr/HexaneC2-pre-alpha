package core

import (
	"bufio"
	"debug/pe"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
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

func (h *HexaneConfig) GetEmbededStrings(strList []string) []byte {
	var stream = new(Stream)

	stream.PackString(string(h.Key))

	if h.Implant.ProfileTypeId == TRANSPORT_HTTP {
		stream.PackDword(1)
	} else if h.Implant.ProfileTypeId == TRANSPORT_PIPE {
		stream.PackDword(0)
	}

	stream.PackDword(1) // Ctx->LE == TRUE

	for _, str := range strList {
		stream.PackString(str)
	}

	return stream.Buffer
}

func (h *HexaneConfig) RunCommand(cmd string) error {
	var (
		Command *exec.Cmd
		Log     *os.File
		LogName string
		err     error
	)

	LogName = LogsPath + "/" + strconv.Itoa(int(h.Implant.PeerId)) + "-error.log"
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

func (h *HexaneConfig) CompileObject(command string, targets, flags, includes []string, definitions map[string][]byte, output string) error {
	var (
		Command string
		err     error
	)

	Command += command

	if definitions == nil {
		definitions = make(map[string][]byte)
	}

	if h.Compiler.Debug {
		definitions["DEBUG"] = nil
	}

	if command != h.Compiler.Ar && command != h.Compiler.Linker && command != h.Compiler.Assembler {
		if h.Implant.ProfileTypeId == TRANSPORT_HTTP {
			definitions["TRANSPORT_HTTP"] = nil

		} else if h.Implant.ProfileTypeId == TRANSPORT_PIPE {
			definitions["TRANSPORT_PIPE"] = nil
		}
	}

	if includes != nil {
		Command += h.GenerateIncludes(includes)
	}

	if targets != nil {
		Command += h.GenerateArguments(targets)
	}

	if flags != nil {
		Command += h.GenerateArguments(flags)
	}

	if definitions != nil {
		for k, v := range definitions {
			def := map[string][]byte{k: v}
			Command += h.GenerateDefinitions(def)
		}
	}

	Command += fmt.Sprintf(" -o %s ", output)

	if err = h.RunCommand(Command); err != nil {
		return err
	}
	return nil
}
