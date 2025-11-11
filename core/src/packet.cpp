namespace Packet {
    VOID PackInt64 (UINT8 *buffer, UINT64 value) {
        buffer[7] = value & 0xFF; value >>= 8;
        buffer[6] = value & 0xFF; value >>= 8;
        buffer[5] = value & 0xFF; value >>= 8;
        buffer[4] = value & 0xFF; value >>= 8;
        buffer[3] = value & 0xFF; value >>= 8;
        buffer[2] = value & 0xFF; value >>= 8;
        buffer[1] = value & 0xFF; value >>= 8;
        buffer[0] = value & 0xFF;
    }

    VOID PackInt32 (UINT8 *buffer, UINT32 value) {
        buffer[0] = (value >> 24) & 0xFF;
        buffer[1] = (value >> 16) & 0xFF;
        buffer[2] = (value >> 8) & 0xFF;
        buffer[3] = (value) & 0xFF;
    }

    UINT32 ExtractU32 (UINT8 const *buffer) {
        return buffer[0] | (buffer[1] << 8) | (buffer[2] << 16) | (buffer[3] <<24);
    }

    PACKET* CreateTaskResponse(UINT32 cmdId) {
        auto packet = CreatePacketWithHeaders(TypeResponse);
        PackUint32(packet, cmdId);

        return packet;
    }

    PACKET* CreatePacketWithHeaders(UINT32 type) {
        PACKET *packet = CreatePacket();

        PackUint32(packet, Ctx->Config.PeerId);
        PackUint32(packet, Ctx->Session.CurrentTaskId);
        PackUint32(packet, type);

        return packet;
    }

    PACKET* CreatePacket () {
        PACKET *packet = (PACKET*) Ctx->Win32.RtlAllocateHeap(Ctx->Heap, 0, sizeof(PACKET));
		if (!packet) {
			return nullptr;
		}

        packet->MsgData 	= (PBYTE) Ctx->Win32.RtlAllocateHeap(Ctx->Heap, 0, sizeof(UINT8));
        packet->MsgLength 	= 0;
        packet->Next 		= nullptr;
defer:
        return packet;
    }

    VOID DestroyPacket (PACKET** packet) {
        if (*packet) {
            if (*(packet)->MsgData) {
                MemSet(*(packet)->MsgData, 0, *(packet)->MsgLength);
                Ctx->Win32.RtlFreeHeap(Ctx->Heap, 0, *(packet)->MsgData);

                *(packet)->MsgData   	= nullptr;
                *(packet)->PeerId  		= 0;
                *(packet)->TaskId		= 0;
                *(packet)->MsgType     	= 0;
                *(packet)->MsgLength   	= 0;
            }

            Ctx->Win32.HeapFree(Ctx->Heap, 0, packet);
			*packet = nullptr;
        }
    }

    VOID PackByte (PACKET* packet, UINT8 data) {
        if (packet) {
            packet->MsgData = (PBYTE) Ctx->Win32.RtlReAllocateHeap(Ctx->Heap, 0, packet->MsgData, packet->MsgLength + sizeof(UINT8));

            MemCopy((PBYTE) packet->MsgData + packet->MsgLength, &data, sizeof(UINT8));
            packet->MsgLength += sizeof(UINT8);
        }
    }

    VOID PackUint64 (PACKET* packet, UINT64 data) {
        if (packet) {
            packet->MsgData = (PBYTE) Ctx->Win32.RtlReAllocateHeap(Ctx->Heap, 0, packet->MsgData, packet->MsgLength + sizeof(UINT64));

            PackInt64((PBYTE) packet->MsgData + packet->MsgLength, data);
            packet->MsgLength += sizeof(UINT64);
        }
    }

    VOID PackUint32 (PACKET* packet, UINT32 data) {
        if (packet) {
            packet->buffer = (PBYTE) Ctx->Win32.RtlReAllocateHeap(Ctx->Heap, 0, packet->MsgData, packet->MsgLength + sizeof(UINT32));

            PackInt32((PBYTE) packet->MsgData + packet->MsgLength, data);
            packet->MsgLength += sizeof(UINT32);
        }
    }

    VOID PackBytes (PACKET* packet, UINT8* data, SIZE_T size) {
        if (packet) {
            if (size) {
                PackUint32(packet, (UINT32) size);
                packet->MsgData = (PBYTE) Ctx->Win32.RtlReAllocateHeap(Ctx->Heap, 0, packet->MsgData, packet->MsgLength + size);

                MemCopy((PBYTE) packet->MsgData + packet->MsgLength, data, size);
                packet->MsgLength += size;
            }
            else {
                PackUint32(packet, 0);
            }
        }
    }

    VOID PackPointer (PACKET* packet, LPVOID pointer) {
#ifdef _M_X64
        PackUint64(packet, (UINT_PTR)pointer);
#elif _M_IX86
        PackUint32(packet, (UINT_PTR)pointer);
#endif
    }

   VOID PackString (PACKET* packet, CHAR* data) {
        PackBytes(packet, (UINT8*) data, MbsLength(data));
    }

    VOID PackWString (PACKET* packet, WCHAR* data) {
        PackBytes(packet, (UINT8*) data, WcsLength(data));
    }

	VOID AddPacket(PACKET* packet) {
		auto head = Ctx->PacketCache;

		if (!Ctx->PacketCache) {
			Ctx->PacketCache = packet;
		} else {
			while (head->Next) {
				head = head->Next;
			}
			head->Next = packet;
		}
	}

	VOID RemovePacket(PACKET* target) {
		PACKET *prev = nullptr;

		if (!Ctx->PacketCache || !target) {
			return;
		}
		for (auto head = Ctx->PacketCache; head; head = head->Next) {
			if (head == target) {
				if (prev) {
					prev->Next = head->Next;
				} else {
					Ctx->PacketCache = head->Next;
				}

				DestroyPacket(head);
				return;

			}
			prev = head;
		}
	}
}
