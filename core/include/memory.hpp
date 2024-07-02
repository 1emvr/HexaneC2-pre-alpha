#ifndef MODULES_MEMORY_HPP
#define MODULES_MEMORY_HPP
#include <core/include/monolith.hpp>
#include <core/include/cruntime.hpp>
#include <core/include/utils.hpp>

namespace Memory {
    FUNCTION HMODULE LdrGetModuleAddress(ULONG hash);
    FUNCTION FARPROC LdrGetSymbolAddress(HMODULE base, ULONG hash);
}
#endif //MODULES_MEMORY_HPP
