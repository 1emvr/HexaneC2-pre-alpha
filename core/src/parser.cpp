#include <core/include/parser.hpp>
namespace Parser {

    VOID ParserBytecpy(_parser *const parser, uint8_t *const dst) {
        HEXANE

        const auto byte = UnpackByte(parser);
        x_memcpy(dst, &byte, 1);
    }

    VOID ParserStrcpy(_parser *const parser, char **const dst, uint32_t *const n_out) {
        HEXANE

        uint32_t length = 0;
        const auto buffer = UnpackString(parser, &length);

        if (length) {
            if (n_out) {
                *n_out = length;
            }
            if ((*dst = S_CAST(char*, x_malloc(length)))) {
                x_memcpy(*dst, buffer, length);
            }
        }
    }

    VOID ParserWcscpy(_parser *const parser, wchar_t **const dst, uint32_t *const n_out) {
        HEXANE

        uint32_t length = 0;
        const auto buffer = UnpackWString(parser, &length);

        if (length) {
            if (n_out) {
                *n_out = length;
            }

            length *= sizeof(wchar_t);
            if ((*dst = S_CAST(wchar_t*, x_malloc(length)))) {
                x_memcpy(*dst, buffer, length);
            }
        }
    }

    VOID ParserMemcpy(_parser *const parser, uint8_t **const dst, uint32_t *const n_out) {
        HEXANE

        uint32_t length = 0;
        const auto buffer = UnpackBytes(parser, &length);

        if (length) {
            if (n_out) {
                *n_out = length;
            }
            if ((*dst = B_PTR(x_malloc(length)))) {
                x_memcpy(*dst, buffer, length);
            }
        }
    }

    VOID CreateParser (_parser *const parser, const uint8_t *const buffer, const uint32_t length) {
        HEXANE

        if (!(parser->Handle = x_malloc(length))) {
            return;
        }

        x_memcpy(parser->Handle, buffer, length);

        parser->Length  = length;
        parser->Buffer  = parser->Handle;
        parser->LE      = Ctx->LE;
    }

    VOID DestroyParser (_parser *const parser) {
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

    BYTE UnpackByte (_parser *const parser) {
        uint8_t data = 0;

        if (parser->Length >= 1) {
            x_memcpy(&data, parser->Buffer, 1);

            parser->Buffer = B_PTR(parser->Buffer) + 1;
            parser->Length -= 1;
        }

        return data;
    }

    SHORT UnpackShort (_parser *const parser) {

        uint16_t data = 0;

        if (parser->Length >= 2) {
            x_memcpy(&data, parser->Buffer, 2);

            parser->Buffer = B_PTR(parser->Buffer) + 2;
            parser->Length -= 2;
        }

        return data;
    }

    ULONG UnpackDword (_parser *const parser) {

        uint32_t data = 0;

        if (!parser || parser->Length < 4) {
            return 0;
        }

        x_memcpy(&data, parser->Buffer, 4);

        parser->Buffer = B_PTR(parser->Buffer) + 4;
        parser->Length -= 4;

        return (parser->LE)
               ? data
               : __builtin_bswap32(S_CAST(int32_t, data));
    }

    ULONG64 UnpackDword64 (_parser *const parser) {

        uint64_t data = 0;

        if (!parser || parser->Length < 8) {
            return 0;
        }

        x_memcpy(&data, parser->Buffer, 4);

        parser->Buffer = B_PTR(parser->Buffer) + 8;
        parser->Length -= 8;

        return (parser->LE)
               ? data
               : __builtin_bswap64(S_CAST(int64_t, data));
    }

    BOOL UnpackBool (_parser *const parser) {

        int32_t data = 0;

        if (!parser || parser->Length < 4) {
            return 0;
        }

        x_memcpy(&data, parser->Buffer, 4);

        parser->Buffer = B_PTR(parser->Buffer) + 4;
        parser->Length -= 4;

        return (parser->LE)
               ? data != 0
               : __builtin_bswap32(data) != 0;
    }

    PBYTE UnpackBytes (_parser *const parser, uint32_t *const n_out) {

        uint8_t *output = { };
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

    LPSTR UnpackString(_parser *const parser, uint32_t *const n_out) {
        return R_CAST(char*, UnpackBytes(parser, n_out));
    }

    LPWSTR UnpackWString(_parser *const parser, uint32_t *const n_out) {
        return R_CAST(wchar_t*, UnpackBytes(parser, n_out));
    }
}