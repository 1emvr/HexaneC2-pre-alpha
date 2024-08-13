#ifndef HEXANE_CORELIB_MEMORY_HPP
#define HEXANE_CORELIB_MEMORY_HPP
#include <core/corelib.hpp>

namespace Memory {
    FUNCTION UINT_PTR GetStackCookie();
    FUNCTION VOID GetProcessHeaps(void *process, uint32_t access, uint32_t pid);
    FUNCTION _resource* GetIntResource(HMODULE base, int RsrcId);

    namespace Context {
        FUNCTION VOID ResolveApi();
        FUNCTION VOID ContextInit();
        FUNCTION VOID ContextDestroy(_hexane *Ctx);
    }

    namespace Modules {
        FUNCTION LDR_DATA_TABLE_ENTRY* GetModuleEntry(uint32_t hash);
        FUNCTION HMODULE GetModuleAddress(PLDR_DATA_TABLE_ENTRY entry);
        FUNCTION FARPROC GetExportAddress(HMODULE Base, ULONG Hash);
        FUNCTION UINT_PTR LoadExportAddress(char *module_name, char *export_name);
    }

    namespace Scanners {
        FUNCTION UINT_PTR RelocateExport(void *process, void *target, size_t size);
        FUNCTION BOOL SigCompare(const uint8_t *data, const char *signature, const char *mask);
        FUNCTION UINT_PTR SignatureScan(uintptr_t start, uint32_t size, const char *signature, const char *mask);
    }
}
#endif //HEXANE_CORELIB_MEMORY_HPP
