package core

import (
	"errors"
	"fmt"
	"hexane_server/cmd"
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

var Characters = "abcdef0123456789"
var RootDirectory = GetCwd() + "/../"

func WrapMessage(typ, msg string) {
	cmd.Cb <- Callback{MsgType: typ, Msg: msg}
}

func GeneratePeerId() uint32 {
	return bits.Reverse32(rand.Uint32())
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

func WriteFile(name string, data []byte) error {
	var (
		err     error
		outFile *os.File
	)

	if outFile, err = os.OpenFile(name, Fstat, 0644); err != nil {
		return err
	}
	defer outFile.Close()

	if _, err = outFile.Write(data); err != nil {
		return err
	}

	return nil
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

func GetCwd() string {
	var (
		err error
		exe string
	)

	if exe, err = os.Executable(); err != nil {
		return ""
	} else {
		return filepath.Dir(exe)
	}
}

func Clear() {
	command := exec.Command("cmd", "/c", "cls")
	command.Stdout = os.Stdout

	if err := command.Run(); err != nil {
		panic(err)
	}
}
