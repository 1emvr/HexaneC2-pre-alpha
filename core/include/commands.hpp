#ifndef HEXANE_CORELIB_COMMANDS_HPP
#define HEXANE_CORELIB_COMMANDS_HPP

#include <core/monolith.hpp>
#include <core/dotnet.hpp>

#include <core/include/cipher.hpp>
#include <core/include/stream.hpp>
#include <core/include/parser.hpp>
#include <core/include/process.hpp>
#include <core/include/dispatch.hpp>
#include <core/include/utils.hpp>

namespace Commands {
	FUNCTION VOID DirectoryList (_parser *parser);
	FUNCTION VOID ProcessModules (_parser *parser);
	FUNCTION VOID ProcessList (_parser *parser);
    	FUNCTION VOID Shutdown(_parser *parser);
	FUNCTION VOID UpdatePeer(_parser *parser);
}

_code_seg(".rdata") _command_map cmd_map[] = {
    { .name = DIRECTORYLIST,    .address = Commands::DirectoryList },
    { .name = PROCESSMODULES,   .address = Commands::ProcessModules },
    { .name = PROCESSLIST,      .address = Commands::ProcessList },
    { .name = SHUTDOWN,         .address = Commands::Shutdown },
    { .name = UPDATEPEER,  	.address = Commands::UpdatePeer },
    { .name = 0,                .address = nullptr }
};
#endif //HEXANE_CORELIB_COMMANDS_HPP
