#include <core/include/parser.hpp>
namespace Parser {

    VOID ParserBytecpy(_parser *const parser, uint8_t *const dst) {

        const auto byte = UnpackByte(parser);
        MemCopy(dst, (void*) &byte, 1);
    }

    VOID ParserStrcpy(_parser *const parser, char **const dst, uint32_t *const n_out) {
        HEXANE;

        uint32_t length     = 0;
        const auto buffer   = UnpackString(parser, &length);

        if (length) {
            if (n_out) {
                *n_out = length;
            }
            if ((*dst = (char*) Malloc(length))) {
                MemCopy(*dst, buffer, length);
            }
        }
    }

    VOID ParserWcscpy(_parser *const parser, wchar_t **const dst, uint32_t *const n_out) {
        HEXANE;

        uint32_t length     = 0;
        const auto buffer   = UnpackWString(parser, &length);

        if (length) {
            if (n_out) {
                *n_out = length;
            }

            length *= sizeof(wchar_t);

            x_assert(*dst = (wchar_t*) Malloc(length));
            MemCopy(*dst, buffer, length);
        }
        defer:
    }

    VOID ParserMemcpy(_parser *const parser, uint8_t **const dst, uint32_t *const n_out) {
        HEXANE;

        uint32_t length     = 0;
        const auto buffer   = UnpackBytes(parser, &length);

        if (length) {
            if (n_out) {
                *n_out = length;
            }

            x_assert(*dst = B_PTR(Malloc(length)));
            MemCopy(*dst, buffer, length);
        }
        defer:
    }

    VOID CreateParser(_parser *parser, uint8_t *buffer, uint32_t length) {
        HEXANE;

        x_assert(parser->handle = Malloc(length));
        MemCopy(parser->handle, buffer, length);

        parser->Length  = length;
        parser->buffer  = parser->handle;

        defer:
    }

    VOID DestroyParser (_parser *const parser) {
        HEXANE;

        if (parser) {
            if (parser->handle) {

                MemSet(parser->handle, 0, parser->Length);
                Free(parser->handle);

                parser->buffer = nullptr;
                parser->handle = nullptr;
            }
        }
    }

    BYTE UnpackByte (_parser *const parser) {
        uint8_t data = 0;

        if (parser->Length >= 1) {
            MemCopy(&data, parser->buffer, 1);

            parser->buffer = B_PTR(parser->buffer) + 1;
            parser->Length -= 1;
        }

        return data;
    }

    SHORT UnpackShort (_parser *const parser) {

        int16_t data = 0;

        if (parser->Length >= 2) {
            MemCopy(&data, parser->buffer, 2);

            parser->buffer = B_PTR(parser->buffer) + 2;
            parser->Length -= 2;
        }

        return data;
    }

    ULONG UnpackUint32 (_parser *const parser) {

        uint32_t data = 0;

        if (!parser || parser->Length < 4) {
            return 0;
        }

        MemCopy(&data, parser->buffer, 4);

        parser->buffer = B_PTR(parser->buffer) + 4;
        parser->Length -= 4;

        return (BSWAP)
               ? __builtin_bswap32((int32_t) data)
               : data;
    }

    ULONG64 UnpackUint64 (_parser *const parser) {

        uint64_t data = 0;

        if (!parser || parser->Length < 8) {
            return 0;
        }

        MemCopy(&data, parser->buffer, 8);

        parser->buffer = B_PTR(parser->buffer) + 8;
        parser->Length -= 8;

        return (BSWAP)
               ? __builtin_bswap64((int64_t) data)
               : data;
    }

    BOOL UnpackBool (_parser *const parser) {

        int32_t data = 0;

        if (!parser || parser->Length < 4) {
            return 0;
        }

        MemCopy(&data, parser->buffer, 4);

        parser->buffer = B_PTR(parser->buffer) + 4;
        parser->Length -= 4;

        return (BSWAP)
               ? __builtin_bswap32(data) != 0
               : data != 0;
    }

    PBYTE UnpackBytes (_parser *const parser, uint32_t *const n_out) {

        uint8_t *output     = { };
        uint32_t length     = 0;

        if (!parser || parser->Length < 4) {
            return nullptr;
        }

        length = UnpackUint32(parser);
        if (n_out) {
            *n_out = length;
        }

        if (!(output = B_PTR(parser->buffer))) {
            return nullptr;
        }

        parser->Length -= length;
        parser->buffer = B_PTR(parser->buffer) + length;

        return output;
    }

    LPSTR UnpackString(_parser *const parser, uint32_t *const n_out) {
        return (char*) UnpackBytes(parser, n_out);
    }

    LPWSTR UnpackWString(_parser *const parser, uint32_t *const n_out) {
        return (wchar_t*) UnpackBytes(parser, n_out);
    }
}