#ifndef MODULES_H
#define MODULES_H
#include <core/corelib.hpp>

namespace Modules {
    PLDR_DATA_TABLE_ENTRY
    FUNCTION
        FindModuleEntry(UINT32 hash);

    FARPROC
    FUNCTION
        FindExportAddress(CONST VOID *base, UINT32 hash);

    BOOL
    FUNCTION
        MapSections(PEXECUTABLE module);

    PEXECUTABLE
    FUNCTION
        LoadModule(UINT32 load_type, WCHAR *filename, UINT8 *memory, UINT32 mem_size, WCHAR *name);
}

#endif //MODULES_H
