#include <core/include/memory.hpp>
namespace Memory {

    HMODULE LdrGetModuleAddress (ULONG Hash) {

        HMODULE Base    = { };
        auto Head       = IN_MEMORY_ORDER_MODULE_LIST;
        auto Next       = Head->Flink;

        while (Next != Head) {
            auto Mod = MODULE_ENTRY(Next);
            auto Name = MODULE_NAME(Mod);

            if (Name) {
                if (Hash - Utils::GetHashFromString(Name, x_wcslen(Name)) == 0) {
                    Base = (HMODULE) Mod->BaseAddress;
                }
            }
            Next = Next->Flink;
        }
        return Base;
    }

    FARPROC LdrGetSymbolAddress (HMODULE Base, ULONG Hash) {

        FARPROC Export = { };

        if (!Base) {
            return nullptr;
        }

        auto DosHead = IMAGE_DOS_HEADER(Base);
        auto NtHead = IMAGE_NT_HEADERS(Base, DosHead);
        auto Exports = IMAGE_EXPORT_DIRECTORY(DosHead, NtHead);

        if ( Exports->AddressOfNames ) {
            auto Ords 	= RVA(PWORD, Base, (long) Exports->AddressOfNameOrdinals);
            auto Fns 	= RVA(PULONG, Base, (long) Exports->AddressOfFunctions);
            auto Names 	= RVA(PULONG, Base, (long) Exports->AddressOfNames);

            for (ULONG i = 0; i < Exports->NumberOfNames; i++) {
                auto Name = RVA(LPSTR, Base, (long) Names[i]);

                if (Hash - Utils::GetHashFromString(Name, x_strlen(Name)) == 0) {
                    Export = (FARPROC) RVA(PULONG, Base, (long) Fns[Ords[i]]);
                }
            }
        }
        return Export;
    }
}