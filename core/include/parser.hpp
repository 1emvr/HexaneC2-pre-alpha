#ifndef HEXANE_PARSER_HPP
#define HEXANE_PARSER_HPP
#include <core/corelib.hpp>

namespace Parser {
    FUNCTION VOID ParserBytecpy(_parser *const parser, uint8_t *const dst);
    FUNCTION VOID ParserStrcpy(_parser *const parser, char **const dst, uint32_t *const n_out);
    FUNCTION VOID ParserWcscpy(_parser *const parser, wchar_t **const dst, uint32_t *const n_out);
    FUNCTION VOID ParserMemcpy(_parser *const parser, uint8_t **const dst, uint32_t *const n_out);
    FUNCTION VOID CreateParser (_parser *const parser, const uint8_t *const buffer, const uint32_t length);
    FUNCTION VOID DestroyParser (_parser *const parser);
    FUNCTION BYTE UnpackByte (_parser *const parser);
    FUNCTION SHORT UnpackShort (_parser *const parser);
    FUNCTION ULONG UnpackDword (_parser *const parser);
    FUNCTION ULONG64 UnpackDword64 (_parser *const parser);
    FUNCTION BOOL UnpackBool (_parser *const parser);
    FUNCTION PBYTE UnpackBytes (_parser *const parser, uint32_t *const n_out);
    FUNCTION LPSTR UnpackString(_parser *const parser, uint32_t *const n_out);
    FUNCTION LPWSTR UnpackWString(_parser *const parser, uint32_t *const n_out);
}
#endif //HEXANE_PARSER_HPP
