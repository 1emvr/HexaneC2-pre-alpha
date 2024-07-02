#ifndef HEXANE_PARSER_HPP
#define HEXANE_PARSER_HPP
#include <include/monolith.hpp>
#include <include/cruntime.hpp>

namespace Parser {

    FUNCTION VOID ParserStrcpy(PPARSER Parser, LPSTR *Dst);
    FUNCTION VOID ParserWcscpy(PPARSER Parser, LPWSTR *Dst);
    FUNCTION VOID ParserMemcpy(PPARSER Parser, PBYTE *Dst);
    FUNCTION VOID CreateParser(PPARSER Parser, PBYTE buffer, DWORD size);
    FUNCTION VOID DestroyParser(PPARSER Parser);
    FUNCTION BYTE UnpackByte(PPARSER parser);
    FUNCTION SHORT UnpackShort(PPARSER parser);
    FUNCTION DWORD UnpackDword(PPARSER parser);
    FUNCTION DWORD64 UnpackDword64(PPARSER parser);
    FUNCTION BOOL UnpackBool(PPARSER parser);
    FUNCTION PBYTE UnpackBytes(PPARSER parser, PDWORD cbOut);
    FUNCTION LPSTR UnpackString(PPARSER parser, PDWORD cbOut);
    FUNCTION LPWSTR UnpackWString(PPARSER parser, PDWORD cbOut);
}

#endif //HEXANE_PARSER_HPP
