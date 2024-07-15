#ifndef HEXANE_CORELIB_MEMORY_HPP
#define HEXANE_CORELIB_MEMORY_HPP
#include <monolith.hpp>
#include <core/include/corelib.hpp>
#include <core/include/cruntime.hpp>
#include <core/include/names.hpp>
#include <core/include/utils.hpp>

namespace Memory {
    FUNCTION VOID       ResolveApi();
    FUNCTION VOID       ContextInit();
    FUNCTION HMODULE    LdrGetModuleAddress(ULONG hash);
    FUNCTION FARPROC    LdrGetSymbolAddress(HMODULE base, ULONG hash);
    FUNCTION UINT_PTR   LdrGetExport(PBYTE Module, PBYTE Export);
    FUNCTION ORSRC      LdrGetIntResource(HMODULE Base, INT RsrcId);
    FUNCTION UINT_PTR   MmCaveHunter(HANDLE Proc, UINT_PTR Export, SIZE_T Size);
}
#endif //HEXANE_CORELIB_MEMORY_HPP
