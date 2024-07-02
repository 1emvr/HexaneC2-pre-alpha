#include <include/stream.hpp>
namespace Stream {

    VOID PackInt64 (PBYTE buffer, UINT64 value) {

        buffer[7] = value & 0xFF; value >>= 8;
        buffer[6] = value & 0xFF; value >>= 8;
        buffer[5] = value & 0xFF; value >>= 8;
        buffer[4] = value & 0xFF; value >>= 8;
        buffer[3] = value & 0xFF; value >>= 8;
        buffer[2] = value & 0xFF; value >>= 8;
        buffer[1] = value & 0xFF; value >>= 8;
        buffer[0] = value & 0xFF;
    }

    VOID PackInt32 (PBYTE buffer, UINT32 value) {

        buffer[0] = (value >> 24) & 0xFF;
        buffer[1] = (value >> 16) & 0xFF;
        buffer[2] = (value >> 8) & 0xFF;
        buffer[3] = (value) & 0xFF;
    }

    uint32_t ExtractU32 (PBYTE Buffer) {
        return Buffer[0] | (Buffer[1] << 8) | (Buffer[2] << 16) | (Buffer[3] <<24);
    }

    PSTREAM CreateStreamWithHeaders(DWORD MsgType) {
        HEXANE

        PSTREAM Stream = CreateStream();

        PackDword(Stream, Ctx->Session.PeerId);
        PackDword(Stream, Ctx->Session.CurrentTaskId);
        PackDword(Stream, MsgType);

        return Stream;
    }

    PSTREAM CreateStream () {
        HEXANE

        PSTREAM stream = { };

        if (
            !(stream            = (PSTREAM) Ctx->Nt.RtlAllocateHeap(Ctx->Heap, HEAP_ZERO_MEMORY, sizeof(STREAM))) ||
            !(stream->Buffer    = Ctx->Nt.RtlAllocateHeap(Ctx->Heap, HEAP_ZERO_MEMORY, sizeof(BYTE)))) {
            return_defer(ntstatus);
        }

        stream->Length 	= 0;
        stream->Next 	= nullptr;

        defer:
        return stream;
    }

    VOID DestroyStream (PSTREAM stream) {
        HEXANE

        if (stream) {
            if (stream->Buffer) {

                x_memset(stream->Buffer, 0, stream->Length);
                Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, stream->Buffer);

                stream->Buffer = nullptr;
                stream->Length = 0;
            }

            Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, stream);
        }
    }

    VOID PackByte (PSTREAM stream, BYTE data) {
        HEXANE

        if (stream) {
            stream->Buffer = Ctx->Nt.RtlReAllocateHeap(Ctx->Heap, HEAP_ZERO_MEMORY, stream->Buffer, stream->Length + sizeof(BYTE));

            x_memcpy(B_PTR(stream->Buffer) + stream->Length, &data, sizeof(BYTE));
            stream->Length += sizeof(BYTE);
        }
    }

    VOID PackDword64 (PSTREAM stream, DWORD64 data) {
        HEXANE

        if (stream) {
            stream->Buffer = Ctx->Nt.RtlReAllocateHeap(Ctx->Heap, HEAP_ZERO_MEMORY, stream->Buffer, stream->Length + sizeof(UINT64));

            PackInt64(B_PTR(stream->Buffer) + stream->Length, data);
            stream->Length += sizeof(UINT64);
        }
    }

    VOID PackDword (PSTREAM stream, DWORD data) {
        HEXANE

        if (stream) {
            stream->Buffer = Ctx->Nt.RtlReAllocateHeap(Ctx->Heap, HEAP_ZERO_MEMORY, stream->Buffer, stream->Length + sizeof(DWORD));

            PackInt32(B_PTR(stream->Buffer) + stream->Length, data);
            stream->Length += sizeof(DWORD);
        }
    }

    VOID PackBool (PSTREAM stream, BOOL data) {
        HEXANE

        if (stream) {
            stream->Buffer = Ctx->Nt.RtlReAllocateHeap(Ctx->Heap, HEAP_ZERO_MEMORY, stream->Buffer, stream->Length + sizeof(BOOL));

            PackInt32(B_PTR(stream->Buffer) + stream->Length, data ? TRUE : FALSE);
            stream->Length += sizeof(BOOL);
        }
    }

    VOID PackBytes (PSTREAM stream, PBYTE data, SIZE_T size) {
        HEXANE

        if (stream) {
            PackDword(stream, U32(size));

            if (size) {
                stream->Buffer = Ctx->Nt.RtlReAllocateHeap(Ctx->Heap, HEAP_ZERO_MEMORY, stream->Buffer, stream->Length + size);

                x_memcpy(B_PTR(stream->Buffer) + stream->Length, data, size);
                stream->Length += size;
            }
        }
    }

    VOID PackPointer (PSTREAM stream, PVOID pointer) {
        PackDword64(stream, U64(pointer));
    }

    VOID PackString (PSTREAM stream, PCHAR data) {
        PackBytes(stream, B_PTR(data), x_strlen(S_PTR(data)));
    }

    VOID PackWString (PSTREAM stream, PWCHAR data) {
        PackBytes(stream, B_PTR(data), x_wcslen(W_PTR(data)));
    }
}

namespace Parser {

    VOID ParserStrcpy(PPARSER Parser, LPSTR *Dst) {
        HEXANE

        DWORD Length  = 0;
        LPSTR Buffer  = UnpackString(Parser, &Length);

        *Dst = (LPSTR) Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, Length);
        if (*Dst) {
            x_memcpy(*Dst, Buffer, Length);
        }
    }

    VOID ParserWcscpy(PPARSER Parser, LPWSTR *Dst) {
        HEXANE

        DWORD Length  = 0;
        LPWSTR Buffer  = UnpackWString(Parser, &Length);

        *Dst = (LPWSTR) Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, (Length * sizeof(WCHAR)) + sizeof(WCHAR));
        if (*Dst) {
            x_memcpy(*Dst, Buffer, Length * sizeof(WCHAR));
        }
    }

    VOID ParserMemcpy(PPARSER Parser, PBYTE *Dst) {
        HEXANE

        DWORD Length = 0;
        PBYTE Buffer = UnpackBytes(Parser, &Length);

        *Dst = (PBYTE) Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, Length);
        if (*Dst) {
            x_memcpy(*Dst, Buffer, Length);
        }
    }

    VOID CreateParser (PPARSER Parser, PBYTE Buffer, DWORD Length) {
        HEXANE

        if (!(Parser->Handle = Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, Length))) {
            return;
        }

        x_memcpy(Parser->Handle, Buffer, Length);

        Parser->Length = Length;
        Parser->Buffer = Parser->Handle;
        Parser->Little = Ctx->LE;
    }

    VOID DestroyParser (PPARSER Parser) {
        HEXANE

        if (Parser) {
            if (Parser->Handle) {

                MmSecureZero(Parser->Handle, Parser->Length);
                Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, Parser->Handle);

                Parser->Buffer = nullptr;
                Parser->Handle = nullptr;
            }
        }
    }

    BYTE UnpackByte (PPARSER Parser) {
        BYTE intBytes = 0;

        if (Parser->Length >= 1) {
            x_memcpy(&intBytes, Parser->Buffer, 1);

            Parser->Buffer = B_PTR(Parser->Buffer) + 1;
            Parser->Length -= 1;
        }

        return intBytes;
    }

    SHORT UnpackShort (PPARSER Parser) {

        SHORT intBytes = 0;

        if (Parser->Length >= 2) {
            x_memcpy(&intBytes, Parser->Buffer, 2);

            Parser->Buffer = B_PTR(Parser->Buffer) + 2;
            Parser->Length -= 2;
        }
        return intBytes;
    }

    DWORD UnpackDword (PPARSER Parser) {

        DWORD intBytes = 0;

        if (!Parser || Parser->Length < 4) {
            return 0;
        }
        x_memcpy(&intBytes, Parser->Buffer, 4);

        Parser->Buffer = B_PTR(Parser->Buffer) + 4;
        Parser->Length -= 4;

        return (Parser->Little)
               ?(DWORD) intBytes
               :(DWORD) __builtin_bswap32(intBytes);
    }

    DWORD64 UnpackDword64 (PPARSER Parser) {

        DWORD64 intBytes = 0;

        if (!Parser || Parser->Length < 8) {
            return 0;
        }
        x_memcpy(&intBytes, Parser->Buffer, 4);

        Parser->Buffer = B_PTR(Parser->Buffer) + 8;
        Parser->Length -= 8;

        return (Parser->Little)
               ?(DWORD64) intBytes
               :(DWORD64) __builtin_bswap64(intBytes);
    }

    BOOL UnpackBool (PPARSER Parser) {

        INT32 intBytes = 0;

        if (!Parser || Parser->Length < 4) {
            return 0;
        }
        x_memcpy(&intBytes, Parser->Buffer, 4);

        Parser->Buffer = B_PTR(Parser->Buffer) + 4;
        Parser->Length -= 4;

        return (Parser->Little)
               ?(BOOL) intBytes != 0
               :(BOOL) __builtin_bswap32(intBytes) != 0;
    }

    PBYTE UnpackBytes (PPARSER Parser, PDWORD cbOut) {

        DWORD length = 0;
        PBYTE output = { };

        if (!Parser || Parser->Length < 4) {
            return nullptr;
        }

        x_memcpy(&length, Parser->Buffer, 4);

        Parser->Buffer = B_PTR(Parser->Buffer) + 4;
        Parser->Length -= 4;

        if (!Parser->Little) {
            length = __builtin_bswap32(length);
        }
        if (cbOut) {
            *cbOut = length;
        }

        output = B_PTR(Parser->Buffer);
        if (output == nullptr) {
            return nullptr;
        }

        Parser->Length -= length;
        Parser->Buffer = B_PTR(Parser->Buffer) + length;

        return output;
    }

    LPSTR UnpackString(PPARSER Parser, PDWORD cbOut) {
        return (LPSTR) UnpackBytes(Parser, cbOut);
    }

    LPWSTR UnpackWString(PPARSER Parser, PDWORD cbOut) {
        return (LPWSTR) UnpackBytes(Parser, cbOut);
    }
}
