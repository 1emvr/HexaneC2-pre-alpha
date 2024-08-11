#ifndef HEXANE_PARSER_HPP
#define HEXANE_PARSER_HPP
#include <core/corelib.hpp>

namespace Parser {
    FUNCTION VOID ParserBytecpy(_parser *parser, uint8_t *dst);
    FUNCTION VOID ParserStrcpy(_parser *parser, char **dst, uint32_t *n_out);
    FUNCTION VOID ParserWcscpy(_parser *parser, wchar_t **dst, uint32_t *n_out);
    FUNCTION VOID ParserMemcpy(_parser *parser, uint8_t **dst, uint32_t *n_out);
    FUNCTION VOID CreateParser(_parser *parser, uint8_t *buffer, uint32_t size);
    FUNCTION VOID DestroyParser(_parser *parser);
    FUNCTION BYTE UnpackByte(_parser *parser);
    FUNCTION SHORT UnpackShort(_parser *parser);
    FUNCTION ULONG UnpackDword(_parser *parser);
    FUNCTION DWORD64 UnpackDword64(_parser *parser);
    FUNCTION BOOL UnpackBool(_parser *parser);
    FUNCTION PBYTE UnpackBytes(_parser *parser, uint32_t *n_out);
    FUNCTION LPSTR UnpackString(_parser *parser, uint32_t *n_out);
    FUNCTION LPWSTR UnpackWString(_parser *parser, uint32_t *n_out);
}
#endif //HEXANE_PARSER_HPP
