#ifndef HEXANE_PARSER_HPP
#define HEXANE_PARSER_HPP
#include <core/include/monolith.hpp>
#include <core/include/cruntime.hpp>

namespace Parser {

    FUNCTION VOID ParserStrcpy(PPARSER Parser, LPSTR *Dst);
    FUNCTION VOID ParserWcscpy(PPARSER Parser, LPWSTR *Dst);
    FUNCTION VOID ParserMemcpy(PPARSER Parser, PBYTE *Dst);
    FUNCTION VOID CreateParser(PPARSER Parser, PBYTE buffer, ULONG size);
    FUNCTION VOID DestroyParser(PPARSER Parser);
    FUNCTION BYTE UnpackByte(PPARSER parser);
    FUNCTION SHORT UnpackShort(PPARSER parser);
    FUNCTION ULONG UnpackDword(PPARSER parser);
    FUNCTION DWORD64 UnpackDword64(PPARSER parser);
    FUNCTION BOOL UnpackBool(PPARSER parser);
    FUNCTION PBYTE UnpackBytes(PPARSER parser, PULONG cbOut);
    FUNCTION LPSTR UnpackString(PPARSER parser, PULONG cbOut);
    FUNCTION LPWSTR UnpackWString(PPARSER parser, PULONG cbOut);
}

#endif //HEXANE_PARSER_HPP
