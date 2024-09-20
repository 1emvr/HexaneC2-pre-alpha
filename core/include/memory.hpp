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
        FUNCTION FARPROC GetExportAddress(const void *base, const uint32_t hash);
        FUNCTION UINT_PTR LoadExport(const char* const module_name, const char* const export_name);
    }

    namespace Execute {
        FUNCTION BOOL ExecuteCommand(_parser &parser);
        FUNCTION BOOL ExecuteShellcode(const _parser &parser);
        FUNCTION VOID LoadObject(_parser parser);
    }
}
#endif //HEXANE_CORELIB_MEMORY_HPP
