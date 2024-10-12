#ifndef HEXANE_CORELIB_COMMANDS_HPP
#define HEXANE_CORELIB_COMMANDS_HPP
#include <core/corelib.hpp>
#include <core/dotnet.hpp>

namespace Commands {
    VOID
    FUNCTION
        DirectoryList(PARSER *parser);

    VOID
    FUNCTION
        ProcessModules(PARSER *parser);

    VOID
    FUNCTION
        ProcessList(PARSER *parser);

    VOID
    FUNCTION
        AddPeer(PARSER *parser);

    VOID
    FUNCTION
        RemovePeer(PARSER *parser);

    VOID
    FUNCTION
        Shutdown(PARSER *parser);

    UINT_PTR
    FUNCTION
        GetCommandAddress(UINT32 name);
}

#endif //HEXANE_CORELIB_COMMANDS_HPP
