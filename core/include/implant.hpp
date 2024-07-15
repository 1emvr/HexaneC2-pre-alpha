#ifndef _HEXANE_BASE_HPP
#define _HEXANE_BASE_HPP
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


namespace Implant {
    EXTERN_C FUNCTION VOID Entrypoint(HMODULE Base);
    FUNCTION VOID MainRoutine();
}

#endif //_HEXANE_BASE_HPP
