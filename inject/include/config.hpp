#ifndef LOADERCFG_HPP
#define LOADERCFG_HPP
#include <monolith.hpp>
#include <core/include/cruntime.hpp>
#include <core/include/parser.hpp>

struct THREADLESS {
    ABUFFER Parent = { };
    ABUFFER Module = { };
    ABUFFER Export = { };
    ABUFFER Loader = { };
    ABUFFER Opcode = { };
};

namespace Config {
    FUNCTION VOID ReadConfig(THREADLESS *Threadless);
}

#endif //LOADERCFG_HPP
