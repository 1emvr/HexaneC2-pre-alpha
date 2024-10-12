#ifndef HEXANE_IMPLANT_CLIENTS_HPP
#define HEXANE_IMPLANT_CLIENTS_HPP
#include <core/corelib.hpp>

namespace Clients {
    PPEER_DATA
    FUNCTION
        GetClient(UINT32 peer_id);

    BOOL
    FUNCTION
        RemoveClient(UINT32 peer_id);

    BOOL
    FUNCTION
        AddClient(CONST WCHAR *pipe_name, UINT32 peer_id);

    VOID
    FUNCTION
        PushClients(VOID);
}
#endif //HEXANE_IMPLANT_CLIENTS_HPP
