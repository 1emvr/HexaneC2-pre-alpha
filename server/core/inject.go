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

	if h.ImplantCFG.Injection.Threadless != nil {
		var (
			loader []byte
			opcode = []byte{0xE8, 0x00, 0x00, 0x00, 0x00}
		)

		LoaderAsm := h.CompilerCFG.BuildDirectory + "/threadless.asm"
		LoaderObj := h.CompilerCFG.BuildDirectory + "/threadless.asm.o"
		LoaderData := h.CompilerCFG.BuildDirectory + "/threadless.bin"

		Execute := h.ImplantCFG.Injection.Threadless.Execute
		InjectCfg.ExecuteObj = Execute + ".o"

		WrapMessage("DBG", fmt.Sprintf("generating execute object %s", Execute))
		if err = h.CompileObject(h.CompilerCFG.Mingw+" -c ", []string{Execute}, h.CompilerCFG.Flags, h.CompilerCFG.Includes, nil, InjectCfg.ExecuteObj); err != nil {
			return nil, err
		}

		WrapMessage("DBG", "generating Threadless loader object")
		if err = h.CompileObject(h.CompilerCFG.Mingw+" -c ", []string{LoaderAsm}, nil, h.CompilerCFG.IncludeDirs, nil, LoaderObj); err != nil {
			return nil, err
		}

		WrapMessage("DBG", "extracting .text from loader object")
		if err = h.RunCommand(h.CompilerCFG.Objcopy + " -j .text -O binary " + LoaderObj + ".o " + LoaderData); err != nil {
			return nil, err
		}

		WrapMessage("DBG", "extracting loader shellcode")
		if loader, err = os.ReadFile(LoaderData); err != nil {
			return nil, err
		}

		WrapMessage("DBG", "allocating injection strings config")
		InjectCfg.Strings = []string{
			h.ImplantCFG.Injection.Threadless.ProcName,
			h.ImplantCFG.Injection.Threadless.ModuleName,
			h.ImplantCFG.Injection.Threadless.FuncName,
			string(opcode),
			string(loader),
		}
	}

	return InjectCfg, nil
}
