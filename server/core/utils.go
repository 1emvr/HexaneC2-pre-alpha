package core

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/bits"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func WrapMessage(typ, msg string) {
	Cb <- Message{MsgType: typ, Msg: msg}
}

func DQuote(str string) string {
	return fmt.Sprintf("\"%s\"", str)
}

func SQuote(str string) string {
	return fmt.Sprintf("'%s'", str)
}

func Tick(str string) string {
	return fmt.Sprintf("`%s`", str)
}

func GeneratePeerId() uint32 {
	return bits.Reverse32(rand.Uint32())
}

func matchB(a, b []byte) bool {

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func PrintChannel(cb chan Message, exit chan bool) {

	for {
		select {
		case x := <-exit:
			if x {
				return
			}
		case m := <-cb:
			if !Debug && m.MsgType == "DBG" {
				continue
			}

			fmt.Println(fmt.Sprintf("[%s] %s", m.MsgType, m.Msg))
		}
	}
}

func EggHuntDoubleD(data []byte, egg []byte) (int, error) {
	eggLen := len(egg)
	dataLen := len(data)

	for i := 0; i <= dataLen-eggLen; i++ {

		if matchB(data[i:i+eggLen], egg) {

			if i+4+eggLen > dataLen {
				return -1, fmt.Errorf("out-of-bounds read in egg hunting")
			}
			if matchB(data[i+4:i+4+eggLen], egg) {
				return i, nil
			}
		}
	}
	return -1, fmt.Errorf("egg was not found")
}

func GenerateUuid(n int) string {
	var (
		indexBits = 4
		indexMask = 1<<indexBits - 1
		indexMax  = 63 / indexBits
		seed      = rand.NewSource(time.Now().UnixNano())
	)

	buffer := make([]byte, n)

	for i, cache, remain := n-1, seed.Int63(), indexMax; i >= 0; {
		if remain == 0 {
			cache, remain = seed.Int63(), indexMax
		}
		if idx := int(cache & int64(indexMask)); idx < len(Characters) {
			buffer[i] = Characters[idx]
			i--
		}
		cache >>= indexBits
		remain--
	}
	return string(buffer)
}

func CreatePath(path string, modeperm os.FileMode) error {
	var err error

	if _, err = os.Stat(path); err != nil {
		if err = os.Mkdir(path, modeperm); err != nil {
			return err
		}
	}
	return nil
}

func WriteFile(name string, data []byte) error {
	var (
		err     error
		outFile *os.File
	)

	if outFile, err = os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644); err != nil {
		return err
	}
	defer func() {
		if err = outFile.Close(); err != nil {
			WrapMessage("ERR", fmt.Sprintf("Error closing output file: %v", err))
		}
	}()

	WrapMessage("DBG", "creating "+name)

	writer := bufio.NewWriter(outFile)
	if _, err = writer.WriteString(string(data)); err != nil {
		return err
	}

	if err = writer.Flush(); err != nil {
		return err
	}

	return nil
}

func FindFiles(path string) ([]os.DirEntry, error) {
	var (
		files []os.DirEntry
		err   error
	)

	if files, err = os.ReadDir(path); err != nil {
		return nil, err
	}

	return files, nil
}

func SearchFile(rootPath string, fileName string) error {
	var (
		files []os.DirEntry
		found bool
		err   error
	)

	if files, err = FindFiles(rootPath); err != nil {
		return err
	}

	for _, file := range files {
		if file.Name() == fileName {
			found = true
		}
	}

	if !found {
		return FileNotFound
	} else {
		return nil
	}
}

func MoveFile(srcPath, dstPath string) error {
	var err error

	fileName := filepath.Base(srcPath)
	dstFile := filepath.Join(dstPath, fileName)

	if err = os.MkdirAll(dstPath, os.ModePerm); err != nil {
		return err
	}

	if err = os.Rename(srcPath, dstFile); err != nil {
		return err
	}

	return nil
}

func CreateTemp(tmpPath string) error {
	var err error

	if _, err = os.Stat(tmpPath); err != nil {
		if os.IsNotExist(err) {
			if err = os.MkdirAll(tmpPath, os.ModePerm); err != nil {
				return err
			}
		} else {
			return err
		}
	}

	return nil
}

func GetCwd() string {
	var (
		err error
		exe string
	)

	if exe, err = os.Executable(); err != nil {
		WrapMessage("ERR", fmt.Sprintf("Error getting cwd: %v", err))
		return ""
	} else {
		return filepath.Dir(exe)
	}
}

func Clear() {
	command := exec.Command("bash", "-c", "clear")
	command.Stdout = os.Stdout

	if err := command.Run(); err != nil {
		panic(err)
	}
}

func HookVCVars() error {
	var (
		err      error
		vcvars   []byte
		env_vars []byte
	)

	hook := []byte("set > %TMP%/vcvars.txt")
	err = filepath.Walk(VCVarsInstall, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && info.Name() == "vcvarsall.bat" {
			VCVarsInstall = path
			return filepath.SkipDir
		}

		return nil
	})
	if err != nil {
		return err
	}

	if vcvars, err = ioutil.ReadFile(VCVarsInstall); err != nil {
		return err
	}

	if !bytes.Contains(vcvars, hook) {
		vcvars = append(vcvars, []byte("\n")...)
		vcvars = append(vcvars, hook...)
	}

	if err = ioutil.WriteFile(VCVarsInstall, vcvars, 0644); err != nil {
		return err
	}

	if err = RunCommand(VCVarsInstall, "hook_vcvars"); err != nil {
		return err
	}

	temp_file := filepath.Join(os.TempDir(), "vcvars.txt")
	if env_vars, err = ioutil.ReadFile(temp_file); err != nil {
		return err
	}

	lines := strings.Split(string(env_vars), "\n")

	for _, line := range lines {
		parts := bytes.SplitN([]byte(line), []byte("="), 2)

		if len(parts) == 2 {
			k := string(parts[0])
			v := string(parts[1])

			if err = os.Setenv(k, v); err != nil {
				return err
			}
		}
	}

	verify := []string{"TMP", "INCLUDE", "LIB", "LIBPATH"}

	for _, key := range verify {
		value := os.Getenv(key)

		if value == "" {
			return fmt.Errorf("env var %s not set", key)
		}
	}

	WrapMessage("INF", "msvc environment context loaded")
	return nil
}

func (h *HexaneConfig) ReadJson(cfgPath string) error {
	var (
		err    error
		buffer []byte
	)

	if buffer, err = os.ReadFile(cfgPath); err != nil {
		return err
	}
	if err = json.Unmarshal(buffer, &h.UserConfig); err != nil {
		return err
	}

	if ShowConfigs {
		jsonData, err := json.MarshalIndent(h.UserConfig, "", "\t")
		if err != nil {
			return err
		}

		WrapMessage("INF", "Unmarshalled data:")
		fmt.Println(string(jsonData))
	}

	return nil
}

func MergeMaps(m1 map[string][]byte, m2 map[string][]byte) map[string][]byte {
	buffer := make(map[string][]byte)

	for k, v := range m1 {
		buffer[k] = v
	}
	for k, v := range m2 {
		buffer[k] = v
	}

	return buffer
}

func MapToStruct(m interface{}, result interface{}) error {
	var (
		err  error
		data []byte
	)
	if data, err = json.Marshal(m); err != nil {
		return err
	}

	return json.Unmarshal(data, result)
}

func CreateCppArray(buffer []byte, length int) []byte {

	array := "{"

	for i := range buffer {
		if i == length-1 {
			array += fmt.Sprintf("0x%02X", buffer[i])
		} else {
			array += fmt.Sprintf("0x%02X,", buffer[i])
		}
	}
	array += "}"
	return []byte(array)
}

func ParseWorkingHours(WorkingHours string) (int32, error) {
	var (
		err             error
		match           bool
		IntWorkingHours int32 = 0
	)

	if WorkingHours != "" {
		match, err = regexp.MatchString("^[12]?[0-9]:[0-6][0-9]-[12]?[0-9]:[0-6][0-9]$", WorkingHours)

		if err != nil || !match {
			return IntWorkingHours,
				errors.New("failed to parse working hours: invalid format. Usage: 8:00-17:00")
		}

		startAndEnd := strings.Split(WorkingHours, "-")
		StartHourAndMinutes := strings.Split(startAndEnd[0], ":")
		endHourAndMinutes := strings.Split(startAndEnd[1], ":")

		startHour, _ := strconv.Atoi(StartHourAndMinutes[0])
		startMinute, _ := strconv.Atoi(StartHourAndMinutes[1])
		endHour, _ := strconv.Atoi(endHourAndMinutes[0])
		endMinute, _ := strconv.Atoi(endHourAndMinutes[1])

		if startHour < 0 || startHour > 24 || endHour < 0 || endHour > 24 || startMinute < 0 || startMinute > 60 {
			return IntWorkingHours, errors.New("failed to parse working hours: invalid hour or minutes")
		}
		if endHour < startHour || (startHour == endHour && endMinute <= startMinute) {
			return IntWorkingHours, errors.New("failed to parse working hours: overlapping start and end times. End cannot be sooner than start")
		}
		// enabled bit
		IntWorkingHours |= 1 << 22
		IntWorkingHours |= (int32(startHour) & 0b011111) << 17
		IntWorkingHours |= (int32(startMinute) & 0b111111) << 11
		IntWorkingHours |= (int32(endHour) & 0b011111) << 6
		IntWorkingHours |= (int32(endMinute) & 0b111111) << 0
	}
	return IntWorkingHours, err
}

func DbgPrintBytes(tag string, buffer []byte) string {
	var str = fmt.Sprintf(tag + " ")

	for i := range buffer {
		str += fmt.Sprintf("%x ", buffer[i])
	}

	str += fmt.Sprintf("\n")
	return str
}

func FormatSize(size uint64) string {
	const (
		KB = 1 << (10 * iota)
		MB
		GB
	)

	switch {
	case size >= GB:
		return fmt.Sprintf("%.2f GB", float64(size)/GB)

	case size >= MB:
		return fmt.Sprintf("%.2f MB", float64(size)/MB)

	case size >= KB:
		return fmt.Sprintf("%.2f KB", float64(size)/KB)

	default:
		return "null"
	}
}
