#ifndef _HEXANE_BASE_HPP
#define _HEXANE_BASE_HPP
#include <core/include/monolith.hpp>
#include <core/include/cruntime.hpp>
#include <core/include/network.hpp>
#include <core/include/memory.hpp>
#include <core/include/message.hpp>
#include <core/include/cipher.hpp>
#include <core/include/opsec.hpp>
#include <core/include/names.hpp>
#include <core/include/utils.hpp>

namespace Core {
    FUNCTION VOID HandleTask(ULONG msgType);
    FUNCTION VOID ResolveApi();
    FUNCTION VOID ReadConfig();
    FUNCTION VOID MainRoutine();
}

#endif //_HEXANE_BASE_HPP
