#ifndef HEXANE_IMPLANT_OBJECTS_HPP
#define HEXANE_IMPLANT_OBJECTS_HPP
#include <core/corelib.hpp>

namespace Objects {
    FUNCTION LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS exception);
    FUNCTION VOID WrapperFunction(void *address, void *args, size_t size);
    FUNCTION BOOL ProcessSymbol(char* sym_string, void** pointer);
    FUNCTION BOOL ExecuteFunction(_executable* object, char* function, void* args, size_t size);
    FUNCTION VOID Cleanup(_executable *object);
    FUNCTION BOOL BaseRelocation(_executable *object);
    FUNCTION SIZE_T GetFunctionMapSize(_executable *object);
    FUNCTION VOID RemoveCoff(_executable *object);
    FUNCTION VOID CoffLoader(char* entrypoint, void* data, void* args, size_t args_size, uint32_t task_id, bool cache);
    FUNCTION VOID CoffThread(_coff_params *params);
}

#endif //HEXANE_IMPLANT_OBJECTS_HPP
