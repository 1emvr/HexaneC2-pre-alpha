#ifndef HEXANE_CORELIB_MEMORY_HPP
#define HEXANE_CORELIB_MEMORY_HPP

#include <core/corelib.hpp>

namespace Memory {
    namespace Methods {
        UINT_PTR
        FUNCTION
            GetStackCookie();

        PRESOURCE
        FUNCTION
            GetIntResource(HMODULE base, INT rsrc_id);

        PEXECUTABLE
        FUNCTION
            CreateImageData(UINT8 *data);

    }

    namespace Context {
        BOOL
        FUNCTION
            ContextInit();

        VOID
        FUNCTION
            ContextDestroy();
    }

    namespace Modules {
        PLDR_DATA_TABLE_ENTRY
        FUNCTION
            GetModuleEntry(UINT32 HASH);

        FARPROC
        FUNCTION
            GetExportAddress(CONST VOID *base, UINT32 hash);

        UINT_PTR
        FUNCTION
            LoadExport(CONST CHAR *module_name, CONST CHAR *export_name);
    }

    namespace Execute {
        BOOL
        FUNCTION
            ExecuteCommand(PARSER parser);

        BOOL
        FUNCTION
            ExecuteShellcode(PARSER parser);

        VOID
        FUNCTION
            LoadObject(PARSER parser);
    }
}
#endif //HEXANE_CORELIB_MEMORY_HPP
