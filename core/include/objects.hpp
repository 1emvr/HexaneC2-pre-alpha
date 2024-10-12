#ifndef HEXANE_IMPLANT_OBJECTS_HPP
#define HEXANE_IMPLANT_OBJECTS_HPP
#include <core/corelib.hpp>

namespace Objects {
    LONG
    WINAPI
    FUNCTION
        ExceptionHandler(PEXCEPTION_POINTERS exception);

    VOID
    FUNCTION
        CoffLoader(CHAR *entrypoint, VOID *data, VOID *args, SIZE_T args_size, UINT32 task_id, BOOL cache);

    BOOL
    FUNCTION
        ExecuteFunction(EXECUTABLE *object, CHAR *function, VOID *args, SIZE_T size);

    VOID
    FUNCTION
        WrapperFunction(VOID *address, VOID *args, SIZE_T size);

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
        RemoveCoff(EXECUTABLE *object);

    VOID
    FUNCTION
        CoffThread(COFF_PARAMS *params);

    VOID
    FUNCTION
        Cleanup(EXECUTABLE *object);
}

#endif //HEXANE_IMPLANT_OBJECTS_HPP
