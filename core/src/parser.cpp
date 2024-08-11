#include <core/include/parser.hpp>
namespace Parser {

    VOID ParserBytecpy(PPARSER parser, byte *dst) {
        HEXANE

        BYTE byte = Parser::UnpackByte(parser);
        x_memcpy(dst, &byte, 1);
    }

    VOID ParserStrcpy(PPARSER parser, char **dst, uint32_t *n_out) {
        HEXANE

        ULONG length  = 0;
        LPSTR buffer  = UnpackString(parser, &length);

        if (length) {
            if (n_out) {
                *n_out = length;
            }
            if ((*dst = S_CAST(char*, Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, length)))) {
                x_memcpy(*dst, buffer, length);
            }
        }
    }

    VOID ParserWcscpy(PPARSER parser, wchar_t **dst, uint32_t *n_out) {
        HEXANE

        ULONG length  = 0;
        LPWSTR buffer  = UnpackWString(parser, &length);

        if (length) {
            if (n_out) {
                *n_out = length;
            }

            length *= sizeof(wchar_t);
            if ((*dst = S_CAST(wchar_t*, Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, length)))) {
                x_memcpy(*dst, buffer, length);
            }
        }
    }

    VOID ParserMemcpy(PPARSER parser, byte **dst, uint32_t *n_out) {
        HEXANE

        ULONG length = 0;
        PBYTE buffer = UnpackBytes(parser, &length);

        if (length) {
            if (n_out) {
                *n_out = length;
            }
            if ((*dst = B_PTR(Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, length)))) {
                x_memcpy(*dst, buffer, length);
            }
        }
    }

    VOID CreateParser (PPARSER parser, byte *buffer, uint32_t length) {
        HEXANE

        if (!(parser->Handle = Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, length))) {
            return;
        }

        x_memcpy(parser->Handle, buffer, length);

        parser->Length  = length;
        parser->Buffer  = parser->Handle;
        parser->LE      = Ctx->LE;
    }

    VOID DestroyParser (PPARSER parser) {
        HEXANE

        if (parser) {
            if (parser->Handle) {

                x_memset(parser->Handle, 0, parser->Length);
                Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, parser->Handle);

                parser->Buffer = nullptr;
                parser->Handle = nullptr;
            }
        }
    }

    BYTE UnpackByte (PPARSER parser) {
        uint8_t data = 0;

        if (parser->Length >= 1) {
            x_memcpy(&data, parser->Buffer, 1);

            parser->Buffer = B_PTR(parser->Buffer) + 1;
            parser->Length -= 1;
        }

        return data;
    }

    SHORT UnpackShort (PPARSER parser) {

        uint16_t data = 0;

        if (parser->Length >= 2) {
            x_memcpy(&data, parser->Buffer, 2);

            parser->Buffer = B_PTR(parser->Buffer) + 2;
            parser->Length -= 2;
        }

        return data;
    }

    ULONG UnpackDword (PPARSER parser) {

        uint32_t data = 0;

        if (!parser || parser->Length < 4) {
            return 0;
        }

        x_memcpy(&data, parser->Buffer, 4);

        parser->Buffer = B_PTR(parser->Buffer) + 4;
        parser->Length -= 4;

        return (parser->LE)
               ? data
               : __bswapd(S_CAST(int32_t, data));
    }

    ULONG64 UnpackDword64 (PPARSER parser) {

        uint64_t data = 0;

        if (!parser || parser->Length < 8) {
            return 0;
        }

        x_memcpy(&data, parser->Buffer, 4);

        parser->Buffer = B_PTR(parser->Buffer) + 8;
        parser->Length -= 8;

        return (parser->LE)
               ? data
               : __bswapq(S_CAST(int64_t, data));
    }

    BOOL UnpackBool (PPARSER parser) {

        int32_t data = 0;

        if (!parser || parser->Length < 4) {
            return 0;
        }

        x_memcpy(&data, parser->Buffer, 4);

        parser->Buffer = B_PTR(parser->Buffer) + 4;
        parser->Length -= 4;

        return (parser->LE)
               ? data != 0
               : __bswapd(data) != 0;
    }

    PBYTE UnpackBytes (PPARSER parser, uint32_t *n_out) {

        byte *output    = { };
        uint32_t length = 0;

        if (!parser || parser->Length < 4) {
            return nullptr;
        }

        length = UnpackDword(parser);
        if (n_out) {
            *n_out = length;
        }

        if (!(output = B_PTR(parser->Buffer))) {
            return nullptr;
        }

        parser->Length -= length;
        parser->Buffer = B_PTR(parser->Buffer) + length;

        return output;
    }

    LPSTR UnpackString(PPARSER parser, uint32_t *n_out) {
        return R_CAST(char*, UnpackBytes(parser, n_out));
    }

    LPWSTR UnpackWString(PPARSER parser, uint32_t *n_out) {
        return R_CAST(wchar_t*, UnpackBytes(parser, n_out));
    }
}
