#include <core/include/clients.hpp>
namespace Clients {

    VOID ClientPush() {
        HEXANE

        // just fucking send it...
        // todo: may add inbound/outbound tags to headers to avoid confusion

        for (auto client = Ctx->clients; client; client = client->next) {
            // check client pipe for outbound messages

            for (auto msg = Ctx->transport.outbound_queue; msg; msg = msg->next) {
                if (msg->buffer && B_PTR(msg->buffer)[0] != 1) { // make sure we're not bouncing back an outbound message

                    if (Dispatcher::PeekPeerId(msg) == client->peer_id) {
                        auto success = true;
                        // peek inbound/outbound tag
                        // receive logic

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