#ifndef HEXANE_IMPLANT_REGISTRY_HPP
#define HEXANE_IMPLANT_REGISTRY_HPP
#include <core/corelib.hpp>

FUNCTION LPSTR      FormatResultError(LRESULT Result);
FUNCTION LSTATUS    RegCreateSubkey(LPSTR Subkey, LPSTR Name, DWORD Value);
#endif //HEXANE_IMPLANT_REGISTRY_HPP
