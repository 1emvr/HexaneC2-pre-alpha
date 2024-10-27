#ifndef HEXANE_PARSER_HPP
#define HEXANE_PARSER_HPP
#include <core/corelib.hpp>

namespace Parser {

    typedef struct _parser {
        LPVOID  handle;
        LPVOID  buffer;
        ULONG 	length;
    } PARSER, *PPARSER;

    BYTE
    FUNCTION
        UnpackByte(PARSER *parser);

    SHORT
    FUNCTION
        UnpackShort(PARSER *parser);

    ULONG
    FUNCTION
        UnpackUint32(PARSER *parser);

    ULONG64
    FUNCTION
        UnpackUint64(PARSER *parser);

    BOOL
    FUNCTION
        UnpackBool(PARSER *parser);

    UINT8*
    FUNCTION
        UnpackBytes(PARSER *parser, UINT32 *n_out);

    LPSTR
    FUNCTION
        UnpackString(PARSER *parser, UINT32 *n_out);

    LPWSTR
    FUNCTION
        UnpackWString(PARSER *parser, UINT32 *n_out);

    VOID
    FUNCTION
        ParserBytecpy(PARSER *parser, UINT8 *dst);

    VOID
    FUNCTION
        ParserStrcpy(PARSER *parser, CHAR **dst, UINT32 *n_out);

    VOID
    FUNCTION
        ParserWcscpy(PARSER *parser, WCHAR **dst, UINT32 *n_out);

    VOID
    FUNCTION
        ParserMemcpy(PARSER *parser, UINT8 **dst, UINT32 *n_out);

    VOID
    FUNCTION
        CreateParser(PARSER *parser, UINT8 *buffer, UINT32 length);

    VOID
    FUNCTION
        DestroyParser(PARSER *parser);

}
#endif //HEXANE_PARSER_HPP
