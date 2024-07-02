#ifndef MODULES_MEMORY_HPP
#define MODULES_MEMORY_HPP
#include <include/monolith.hpp>
#include <include/cruntime.hpp>
#include <include/hash.hpp>

namespace Memory {
    HMODULE LdrGetModuleAddress(DWORD hash);
    FARPROC LdrGetSymbolAddress(HMODULE base, DWORD hash);
}
#endif //MODULES_MEMORY_HPP
