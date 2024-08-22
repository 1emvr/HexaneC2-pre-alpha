package core

import (
	"bufio"
	"context"
	"debug/pe"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

func (h *HexaneConfig) StripSymbols(output string) error {
	return RunCommand(h.Compiler.Strip+" "+output, strconv.Itoa(int(h.PeerId)))
}

func (h *HexaneConfig) GetBuildType() string {

	if h.UserConfig.Loader != nil {
		return ".dll"
	} else {
		return ".bin"
	}
}

func (h *HexaneConfig) GetTransportType() (string, error) {

	switch h.Implant.ProfileTypeId {
	case TRANSPORT_HTTP:
		return "TRANSPORT_HTTP", nil
	case TRANSPORT_PIPE:
		return "TRANSPORT_PIPE", nil
	default:
		return "", fmt.Errorf("transport type was not defined")
	}
}

func (h *HexaneConfig) GetEmbededStrings(strList []string) []byte {

	stream := new(Stream)
	stream.PackString(string(h.Key))

	switch h.Implant.ProfileTypeId {
	case TRANSPORT_HTTP:
		stream.PackDword(1)
	case TRANSPORT_PIPE:
		stream.PackDword(0)
	default:
		return nil
	}

	stream.PackDword(1) // Ctx->LE == TRUE

	for _, str := range strList {
		stream.PackString(str)
	}

	return stream.Buffer
}

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
		hash := CreateHashMacro(line)
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

func (h *HexaneConfig) EmbedSectionData(path string, data []byte, secSize int) error {
	var (
		readFile *os.File
		readData []byte
		offset   int
		err      error
	)

	if readFile, err = os.OpenFile(path, os.O_RDWR, 0644); err != nil {
		return err
	}
	defer func() {
		err = readFile.Close()
	}()
	if err != nil {
		return err
	}

	if readData, err = ioutil.ReadAll(readFile); err != nil {
		return err
	}

	if offset, err = EggHuntDoubleD(readData, []byte{0x41, 0x41, 0x41, 0x41}); offset == -1 {
		return err
	}

	if len(data) > secSize {
		return fmt.Errorf("data is longer than " + strconv.Itoa(secSize) + " bytes")
	}

	copy(readData[offset:], data)
	remaining := secSize - len(data)

	if remaining > 0 {
		for i := 0; i < remaining; i++ {
			readData[offset+len(data)+i] = 0x00
		}
	}

	if _, err = readFile.WriteAt(readData, 0); err != nil {
		return err
	}

	return nil
}

func (h *HexaneConfig) CopySectionData(path string, out string, target string) error {
	var (
		readFile *os.File
		peFile   *pe.File
		section  *pe.Section
		err      error
	)

	if readFile, err = os.Open(path); err != nil {
		return err
	}
	if peFile, err = pe.NewFile(readFile); err != nil {
		return err
	}
	defer func() {
		if err = readFile.Close(); err != nil {
			WrapMessage("ERR", err.Error())
		}
		if err = peFile.Close(); err != nil {
			WrapMessage("ERR", err.Error())
		}
	}()

	for _, s := range peFile.Sections {
		if s.Name == target {
			section = s
			break
		}
	}

	if section == nil {
		return fmt.Errorf("%s section was not found in %s", target, path)
	}

	outData := make([]byte, section.Size)

	if _, err = readFile.ReadAt(outData, int64(section.Offset)); err != nil {
		return err
	}

	if err = WriteFile(out, outData); err != nil {
		return err
	}

	return nil
}

func (h *HexaneConfig) CompileObject(command, output string, targets, flags, includes []string, definitions map[string][]byte) error {
	var err error

	if definitions == nil {
		definitions = make(map[string][]byte)
	}

	if h.Compiler.Debug {
		if command != h.Compiler.Linker {
			definitions["DEBUG"] = nil
		}
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

	if err = RunCommand(command, strconv.Itoa(int(h.PeerId))); err != nil {
		return err
	}

	return nil
}

func (h *HexaneConfig) CompileSources(module *Module) error {
	var (
		err error
		wg  sync.WaitGroup
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srcPath := filepath.Join(module.RootDirectory, "src")
	entries, err := os.ReadDir(srcPath)

	errCh := make(chan error)

	for _, src := range entries {
		wg.Add(1)

		go func(src os.DirEntry) {
			defer wg.Done()

			target := filepath.Join(srcPath, src.Name())
			obj := filepath.Join(BuildPath, src.Name()+".o")

			var flags []string
			select {
			case <-ctx.Done():
				return

			default:
				switch filepath.Ext(target) {
				case ".asm":

					flags = append(flags, "-f win64")
					err = h.CompileObject(h.Compiler.Assembler, obj, []string{target}, flags, nil, nil)

				case ".cpp":

					flags = append(flags, h.Compiler.Flags...)
					flags = append(flags, "-c")

					err = h.CompileObject(h.Compiler.Mingw, obj, []string{target}, flags, module.Files.IncludeDirectories, module.Definitions)
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

func RunCommand(cmd string, logname string) error {
	var (
		Command *exec.Cmd
		Log     *os.File
		LogName string
		Shell   string
		Flag    string
		err     error
	)

	if runtime.GOOS == "windows" {
		Shell, Flag = "cmd", "/c"
	} else if runtime.GOOS == "linux" {
		Shell, Flag = "bash", "-c"
	}

	LogName = filepath.Join(LogsPath, logname)
	if Log, err = os.Create(LogName); err != nil {
		return err
	}

	defer func() {
		if err = Log.Close(); err != nil {
			WrapMessage("ERR", err.Error())
		}
	}()

	Command = exec.Command(Shell, Flag, cmd)
	Command.Stdout = Log
	Command.Stderr = Log

	if ShowCommands {
		WrapMessage("DBG", "running command : "+Command.String()+"\n")
	}

	if err = Command.Run(); err != nil {
		return fmt.Errorf("check %s for details", LogName)
	}

	return nil
}
