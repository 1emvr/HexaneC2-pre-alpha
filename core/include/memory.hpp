#ifndef MODULES_MEMORY_HPP
#define MODULES_MEMORY_HPP
#include <core/include/monolith.hpp>
#include <core/include/cruntime.hpp>
#include <core/include/hash.hpp>

namespace Memory {
    HMODULE LdrGetModuleAddress(DWORD hash);
    FARPROC LdrGetSymbolAddress(HMODULE base, DWORD hash);
}
#endif //MODULES_MEMORY_HPP
