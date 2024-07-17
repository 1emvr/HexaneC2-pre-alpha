#ifndef HEXANE_CORELIB_COMMANDS_HPP
#define HEXANE_CORELIB_COMMANDS_HPP
#include <monolith.hpp>
#include <core/corelib/corelib.hpp>

namespace Commands {
	FUNCTION VOID DirectoryList (PPARSER Parser);
	FUNCTION VOID ProcessModules (PPARSER Parser);
    FUNCTION VOID Shutdown(PPARSER Parser);
	FUNCTION VOID UpdatePeer(PPARSER Parser);
}
#endif //HEXANE_CORELIB_COMMANDS_HPP