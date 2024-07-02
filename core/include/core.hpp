#ifndef _HEXANE_BASE_HPP
#define _HEXANE_BASE_HPP
#include <include/monolith.hpp>
#include <include/cruntime.hpp>
#include <include/memory.hpp>
#include <include/message.hpp>
#include <include/opsec.hpp>
#include <include/names.hpp>
#include <include/utils.hpp>

namespace Core {
    FUNCTION VOID HandleTask(DWORD msgType);
    FUNCTION VOID ResolveApi();
    FUNCTION VOID ReadConfig();
    FUNCTION VOID MainRoutine();
}

#endif //_HEXANE_BASE_HPP
