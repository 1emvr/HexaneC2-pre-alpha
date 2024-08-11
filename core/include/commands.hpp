#ifndef HEXANE_CORELIB_COMMANDS_HPP
#define HEXANE_CORELIB_COMMANDS_HPP
#include <core/corelib.hpp>

enum CommandType {
	CommandDir          	= 0x00000001,
	CommandMods         	= 0x00000002,
	CommandNoJob        	= 0x00000003,
	CommandShutdown     	= 0x00000004,
	CommandUpdatePeer   	= 0x00000005,
	CommandProcess 		= 0x00000006,
};

namespace Commands {
	FUNCTION VOID DirectoryList (_parser *parser);
	FUNCTION VOID ProcessModules (_parser *parser);
	FUNCTION VOID ProcessList (_parser *parser);
    FUNCTION VOID Shutdown(_parser *parser);
	FUNCTION VOID UpdatePeer(_parser *parser);
}

#endif //HEXANE_CORELIB_COMMANDS_HPP