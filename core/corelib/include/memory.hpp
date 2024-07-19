#ifndef HEXANE_CORELIB_MEMORY_HPP
#define HEXANE_CORELIB_MEMORY_HPP
#include <core/monolith.hpp>
#include <core/corelib/corelib.hpp>

namespace Memory {
    FUNCTION VOID       ResolveApi();
    FUNCTION VOID       ContextInit();
    FUNCTION HMODULE    LdrGetModuleAddress(ULONG hash);
    FUNCTION FARPROC    LdrGetSymbolAddress(HMODULE base, ULONG hash);
    FUNCTION PRSRC      LdrGetIntResource(HMODULE Base, INT RsrcId);
    FUNCTION UINT_PTR   LdrGetExport(LPSTR Module, LPSTR Export);
    FUNCTION UINT_PTR   MmCaveHunter(HANDLE Proc, UINT_PTR Export, SIZE_T Size);
}
#endif //HEXANE_CORELIB_MEMORY_HPP
