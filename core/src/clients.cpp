#include <core/include/clients.hpp>
namespace Clients {

    VOID PushClients() {
        HEXANE

        // just fucking send it...
        for (auto client = Ctx->clients; client; client = client->next) {
            // check client pipe for outbound messages
            // reading logic

            for (auto msg = Ctx->transport.outbound_queue; msg; msg = msg->next) {
                if (msg->buffer && B_PTR(msg->buffer)[0] != 0) {
                    // if message is marked outbound, don't send it inbound by accident

                    if (Dispatcher::PeekPeerId(msg) == client->peer_id) {
                        auto success = true;
                        // peek inbound/outbound tag
                        // writing logic

                        if (success) {
                            Dispatcher::RemoveMessage(msg);
                        }
                    }
                } else {
                    continue;
                }
            }
        }
    }
}