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
            CreateImage(UINT8 *data);

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
            GetModuleEntry(UINT32 hash);

        FARPROC
        FUNCTION
            GetExportAddress(CONST VOID *base, UINT32 hash);

        BOOL
        FUNCTION
            MapSections(PEXECUTABLE module);

	    PEXECUTABLE
        FUNCTION
            LoadModule(UINT32 load_type, WCHAR *filename, UINT8 *memory, UINT32 mem_size, WCHAR *name);
    }

    namespace Execute {
        BOOL
        FUNCTION
            ExecuteCommand(PARSER parser);

        BOOL
        FUNCTION
            ExecuteShellcode(const PARSER &parser);

        VOID
        FUNCTION
            LoadObject(PARSER parser);
    }
}
#endif //HEXANE_CORELIB_MEMORY_HPP
