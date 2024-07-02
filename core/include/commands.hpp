#ifndef _HEXANE_COMMANDS_HPP
#define _HEXANE_COMMANDS_HPP
#include <include/monolith.hpp>
#include <include/cruntime.hpp>
#include <include/process.hpp>
#include <include/message.hpp>
#include <include/stream.hpp>

namespace Commands {
	FUNCTION VOID DirectoryList (PPARSER Parser);
	FUNCTION VOID ProcessModules (PPARSER Parser);
    FUNCTION VOID Shutdown(PPARSER Parser);
	FUNCTION VOID UpdatePeer(PPARSER Parser);
}
#endif //_HEXANE_COMMANDS_HPP