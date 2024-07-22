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
	execute := h.UserConfig.Builder.Loader.Injection.Config.(*Threadless).Execute
	loader := h.UserConfig.Builder.Loader.Injection.Config.(*Threadless).LoaderAsm

	if err = h.CompileObject(h.Compiler.Mingw+" -c ", execute+".o", []string{execute}, h.Compiler.Flags, []string{RootDirectory}, nil); err != nil {
		return nil, err
	}

	if err = h.CompileObject(h.Compiler.Mingw+" -c ", loader+".o", []string{loader}, nil, []string{RootDirectory}, nil); err != nil {
		return nil, err
	}

	if err = h.RunCommand(h.Compiler.Objcopy + " -j .text -O binary " + loader + ".o" + "loader_shc.bin"); err != nil {
		return nil, err
	}

	if bLoader, err = os.ReadFile("loader_shc.bin"); err != nil {
		return nil, err
	}

	return []string{
		h.UserConfig.Builder.Loader.Injection.Config.(*Threadless).TargetProc,
		h.UserConfig.Builder.Loader.Injection.Config.(*Threadless).TargetModule,
		h.UserConfig.Builder.Loader.Injection.Config.(*Threadless).TargetFunc,
		string(opcode),
		string(bLoader),
	}, nil
}
