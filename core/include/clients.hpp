#ifndef HEXANE_IMPLANT_CLIENTS_HPP
#define HEXANE_IMPLANT_CLIENTS_HPP
#include <core/corelib.hpp>

namespace Clients {
    FUNCTION _client* GetClient(const uint32_t peer_id);
    FUNCTION BOOL RemoveClient(const uint32_t peer_id);
    FUNCTION BOOL AddClient(const wchar_t *pipe_name, const uint32_t peer_id);
    FUNCTION VOID PushClients();
}
#endif //HEXANE_IMPLANT_CLIENTS_HPP
