#ifndef HEXANE_PARSER_HPP
#define HEXANE_PARSER_HPP
namespace Parser {
    VOID ParserBytecpy(PARSER* CONST parser, UINT8* CONST dst) {
        const auto byte = UnpackByte(parser);
        MemCopy(dst, (LPVOID) &byte, 1);
    }

    VOID ParserStrcpy(PARSER* CONST parser, CHAR** CONST dst, UINT32 *CONST nOut) {
        UINT32 length    	= 0;
        const auto buffer   = UnpackString(parser, &length);

        if (length) {
            if (nOut) {
                *nOut = length;
            }
            if ((*dst = (CHAR*) Ctx->Win32.RtlAllocateHeap(Ctx->Heap, 0, length))) {
                MemCopy(*dst, buffer, length);
            }
        }
    }

    VOID ParserWcscpy(PARSER* CONST parser, WCHAR** CONST dst, UINT32* CONST nOut) {
        UINT32 length     = 0;
        const auto buffer = UnpackWString(parser, &length);

        if (length) {
            if (nOut) {
                *nOut = length;
            }

            length *= sizeof(WCHAR);

            *dst = (WCHAR*) Ctx->Win32.RtlAllocateHeap(Ctx->Heap, 0, length);
            MemCopy(*dst, buffer, length);
        }
    }

    VOID ParserMemcpy(PARSER* CONST parser, UINT8** CONST dst, UINT32* CONST nOut) {
        UINT32 length     = 0;
        const auto buffer = UnpackBytes(parser, &length);

        if (length) {
            if (nOut) {
                *nOut = length;
            }

            *dst = (PBYTE) Ctx->Win32.RtlAllocateHeap(Ctx->Heap, 0, length);
            MemCopy(*dst, buffer, length);
        }
    }

    VOID CreateParser(PARSER* parser, UINT8* buffer, UINT32 length) {
        parser->Handle = Ctx->Win32.RtlAllocateHeap(Ctx->Heap, 0, length);
        MemCopy(parser->Handle, buffer, length);

        parser->MsgLength  	= length;
        parser->MsgData  	= parser->Handle;
    }

    VOID DestroyParser (PARSER** parser) {
        if (*parser) {
            if ((*parser)->Handle) {
                MemSet(*(parser)->Handle, 0, *(parser)->Length);
                Ctx->Win32.RtlFreeHeap(Ctx->Heap, 0, *(parser)->Handle);

                *(parser)->Buffer = nullptr;
                *(parser)->Handle = nullptr;
            }
			Ctx->Win32.RtlFreeHeap(Ctx->Heap, 0, *packet);
			*packet = nullptr;
        }
    }

    BYTE UnpackByte (PARSER* CONST parser) {
        UINT8 data = 0;

        if (parser->Length >= 1) {
            MemCopy(&data, parser->Buffer, 1);

            parser->Buffer = (PBYTE)parser->Buffer + 1;
            parser->Length -= 1;
        }

        return data;
    }

    SHORT UnpackShort (PARSER* CONST parser) {
        INT16 data = 0;

        if (parser->Length >= 2) {
            MemCopy(&data, parser->Buffer, 2);

            parser->Buffer = (PBYTE) parser->Buffer + 2;
            parser->Length -= 2;
        }

        return data;
    }

    ULONG UnpackUint32 (PARSER* CONST parser) {
        UINT32 data = 0;

        if (!parser || parser->Length < 4) {
            return 0;
        }

        MemCopy(&data, parser->Buffer, 4);

        parser->Buffer = (PBYTE) parser->Buffer + 4;
        parser->Length -= 4;

        return (BSWAP) ? __bswap32((INT32) data) : data;
    }

    ULONG64 UnpackUint64 (PARSER* CONST parser) {
        UINT64 data = 0;

        if (!parser || parser->Length < 8) {
            return 0;
        }

        MemCopy(&data, parser->Buffer, 8);

        parser->Buffer = (PBYTE) parser->Buffer + 8;
        parser->Length -= 8;

        return (BSWAP) ? __bswap64((INT64) data) : data;
    }

    BOOL UnpackBool (PARSER* CONST parser) {
        INT32 data = 0;

        if (!parser || parser->Length < 4) {
            return 0;
        }

        MemCopy(&data, parser->Buffer, 4);

        parser->Buffer = (PBYTE) parser->Buffer + 4;
        parser->Length -= 4;

        return (BSWAP) ? __bswap32(data) != 0 : data != 0;
    }

    PBYTE UnpackBytes (PARSER* CONST parser, UINT32* CONST nOut) {
        UINT8 *output = nullptr;
        UINT32 length = 0;

        if (!parser || parser->Length < 4) {
            return nullptr;
        }

        length = UnpackUint32(parser);
        if (nOut) {
            *nOut = length;
        }

        output = (PBYTE) parser->Buffer; 
		if (!output) {
            return nullptr;
        }

        parser->Length -= length;
        parser->Buffer = (PBYTE) parser->Buffer + length;

        return output;
    }

    LPSTR UnpackString(PARSER* CONST parser, UINT32* CONST nOut) {
        return (CHAR*) UnpackBytes(parser, nOut);
    }

    LPWSTR UnpackWString(PARSER* CONST parser, UINT32* CONST nOut) {
        return (WCHAR*) UnpackBytes(parser, nOut);
    }
}
#endif // HEXANE_PARSER_HPP
