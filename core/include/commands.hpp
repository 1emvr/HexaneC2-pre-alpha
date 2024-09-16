#ifndef HEXANE_CORELIB_COMMANDS_HPP
#define HEXANE_CORELIB_COMMANDS_HPP
#include <core/corelib.hpp>
#include <core/dotnet.hpp>

namespace Commands {
    FUNCTION VOID DirectoryList (_parser *const parser);
    FUNCTION VOID ProcessModules (_parser *const parser);
    FUNCTION VOID ProcessList(_parser *const parser);
    FUNCTION VOID AddPeer(_parser *parser);
    FUNCTION VOID RemovePeer(_parser *parser);
    FUNCTION VOID Shutdown (_parser *parser);
    FUNCTION UINT_PTR GetCommandAddress(const uint32_t name);
}

#endif //HEXANE_CORELIB_COMMANDS_HPP
