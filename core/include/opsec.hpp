#ifndef HEXANE_OPSEC_HPP
#define HEXANE_OPSEC_HPP
#include <core/include/monolith.hpp>
#include <core/include/commands.hpp>
#include <core/include/utils.hpp>

BOOL CheckTime ();
VOID SeCheckDebugger();
VOID SeCheckSandbox();
VOID SeCheckEnvironment();
VOID SeImageCheck(PIMAGE img, PIMAGE proc);
VOID SleepObf();

#endif //HEXANE_OPSEC_HPP
