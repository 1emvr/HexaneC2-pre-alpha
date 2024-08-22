#ifndef HEXANE_CORELIB_COMMANDS_HPP
#define HEXANE_CORELIB_COMMANDS_HPP

#include <core/corelib.hpp>
#include <core/dotnet.hpp>

namespace Commands {
	FUNCTION VOID DirectoryList (_parser *parser);
	FUNCTION VOID ProcessModules (_parser *parser);
	FUNCTION VOID ProcessList(_parser *parser);
	FUNCTION VOID AddPeer(_parser *parser);
	FUNCTION VOID RemovePeer(_parser *parser);
	FUNCTION VOID Shutdown (_parser *parser);
}

#endif //HEXANE_CORELIB_COMMANDS_HPP
