#include <core/include/parser.hpp>
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

                x_memset(Parser->Handle, 0, Parser->Length);
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
