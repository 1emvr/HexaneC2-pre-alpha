#ifndef HEXANE_CORELIB_COMMANDS_HPP
#define HEXANE_CORELIB_COMMANDS_HPP
#include <core/corelib.hpp>

namespace Commands {
	FUNCTION VOID DirectoryList (_parser *parser);
	FUNCTION VOID ProcessModules (_parser *parser);
	FUNCTION VOID ProcessList (_parser *parser);
    FUNCTION VOID Shutdown(_parser *parser);
	FUNCTION VOID UpdatePeer(_parser *parser);
}
#endif //HEXANE_CORELIB_COMMANDS_HPP