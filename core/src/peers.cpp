#include <core/include/peers.hpp>

using namespace Stream;
using namespace Dispatcher;
using namespace Network::Smb;

namespace Peers {

    UINT32 PeekPeerId(_stream *stream) {

        uint32_t pid = 0;
        MemCopy(&pid, B_PTR(stream->buffer), 4);

        return pid;
    }

    _pipe_data* GetPeer(const uint32_t peer_id) {
        HEXANE;

        auto head = ctx->peers;
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

    BOOL RemovePeer(uint32_t peer_id) {
        HEXANE;

        bool success    = true;
        _pipe_data *head   = ctx->peers;
        _pipe_data *target = GetPeer(peer_id);
        _pipe_data *prev   = { };

	    if (!head || !target) {
	        return false;
	    }

        while (head) {
            if (head == target) {
                if (prev) {
                    prev->next = head->next;
                }
                else {
                    ctx->peers = head->next;
                }

                if (head->pipe_name) {
                    MemSet(head->pipe_name, 0, WcsLength(head->pipe_name));
                    Free(head->pipe_name);
                }
                if (head->pipe_handle) {
                    ctx->nt.NtClose(head->pipe_handle);
                    head->pipe_handle = nullptr;
                }

                head->peer_id = 0;
                return true;
            }

            prev = head;
            head = head->next;
        }

        defer:
        return success;
    }

    BOOL AddPeer(const wchar_t *pipe_name, uint32_t peer_id) {
        HEXANE;

        _stream *in = { };
        _pipe_data *peer = { };
        _pipe_data *head = { };

        void *handle = { };
        void *buffer = { };

        DWORD total = 0;
        DWORD read  = 0;

        // first contact
        if (!(handle = ctx->win32.CreateFileW(pipe_name, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr))) {
            if (handle == INVALID_HANDLE_VALUE) {
                return false;
            }

            if (ntstatus == ERROR_PIPE_BUSY) {
                if (!ctx->win32.WaitNamedPipeW(pipe_name, 5000)) {
                    ctx->nt.NtClose(handle);
                    return false;
                }
            }
        }

        do {
            if (ctx->win32.PeekNamedPipe(handle, nullptr, 0, nullptr, &total, nullptr)) {
                if (total) {

                    in = CreateStream();
                    buffer = Malloc(total);

                    if (!ctx->win32.ReadFile(handle, buffer, total, &read, nullptr) || read != total) {
                        ctx->nt.NtClose(handle);
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

        peer = (_pipe_data*) Malloc(sizeof(_pipe_data));
        peer->pipe_handle = handle;

        MemCopy(&peer->peer_id, &peer_id, sizeof(uint32_t));
        MemCopy(peer->pipe_name, pipe_name, WcsLength(pipe_name) * sizeof(wchar_t));

        if (!ctx->peers) {
            ctx->peers = peer;
        }
        else {
            head = ctx->peers;
            do {
                if (head) {
                    if (head->next) {
                        head = head->next;
                    }
                    else {
                        head->next = peer;
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
        HEXANE;

        _stream *in = { };

        uint8_t bound   = 0;
        void *buffer    = { };

        DWORD read  = 0;
        DWORD total  = 0;

        for (auto client = ctx->peers; client; client = client->next) {
            if (!ctx->win32.PeekNamedPipe(client->pipe_handle, &bound, sizeof(uint8_t), nullptr, &read, nullptr) || read != sizeof(uint8_t)) {
                continue;
            }

            if (!ctx->win32.PeekNamedPipe(client->pipe_handle, nullptr, 0, nullptr, &total, nullptr)) {
                continue;
            }

            if (bound == EGRESS && total >= sizeof(uint32_t)) {
                in = CreateStream();
                buffer = Malloc(total);

                if (!ctx->win32.ReadFile(client->pipe_handle, buffer, total, &read, nullptr) || read != total) {
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

        	// TODO: prepend outbound messages with 0, inbound with 1 (questioning if this is necessary)
            for (auto message = ctx->transport.message_queue; message; message = message->next) {
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
